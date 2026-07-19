"""
hydra/services/sync_agent.py — Фоновый агент синхронизации v2.

Проверяет лимиты трафика и сроки действия подписок.
Уведомляет плагины при блокировке пользователя.
Запускается через systemd timer каждые 5 минут.
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, TextIO

from hydra.core.state import update_state
from hydra.plugins.registry import get_enabled
from hydra.services.traffic import check_traffic_limits


SYNC_LOCK = Path("/run/hydra/sync-agent.lock")
WARP_CACHE_FILE = Path("/var/lib/hydra/warp_external.json")
SYNC_LOG = Path("/var/log/hydra/sync-agent.log")


@contextmanager
def _single_run() -> Iterator[bool]:
    """Prevent the timer and an interactive run from overlapping on Linux."""
    if sys.platform == "win32":
        yield True
        return

    handle: TextIO | None = None
    try:
        import fcntl

        SYNC_LOCK.parent.mkdir(parents=True, exist_ok=True)
        handle = SYNC_LOCK.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        if handle is not None:
            handle.close()


def run_sync(
    force_update_check: bool = False,
    force_all_checks: bool = False,
) -> tuple[bool, str]:
    """Run one synchronization cycle and report partial failures to callers."""
    with _single_run() as acquired:
        if not acquired:
            message = "Sync Agent уже выполняется другим процессом"
            _log(message)
            return False, message
        return _run_sync(
            force_update_check=force_update_check,
            force_all_checks=force_all_checks,
        )


def _run_sync(
    force_update_check: bool = False,
    force_all_checks: bool = False,
) -> tuple[bool, str]:
    """
    Основная логика синхронизации:
      1. Проверить лимиты трафика -> заблокировать превысивших
      2. Проверить TTL (срок действия) -> заблокировать истёкших
      3. Уведомить плагины о блокировке
      4. Применить измененный конфиг к службам
    """
    from hydra.core.state import load_state
    now = datetime.now(timezone.utc)

    # Сначала считываем текущие настройки активности
    state = load_state()
    limits_enabled = force_all_checks or state.install.get("sync_limits_enabled", True)
    warp_enabled = force_all_checks or state.install.get("sync_warp_enabled", True)
    updates_enabled = force_all_checks or state.install.get("sync_updates_enabled", True)

    blocked = {}
    failures: list[str] = []
    _log("Sync started" + (" (manual full check)" if force_all_checks else ""))
    if limits_enabled:
        # Refresh counters, evaluate all restrictions and persist the block in one
        # lock transaction. The pending marker survives a crash or failed apply.
        def refresh_and_block(latest):
            exceeded = set(check_traffic_limits(latest))
            blocked_users: dict[str, str] = {}
            for user in latest.users:
                if user.blocked:
                    continue
                reason = ""
                if user.email in exceeded:
                    reason = "traffic limit exceeded"
                elif user.expiry_date:
                    try:
                        dt_str = user.expiry_date
                        if dt_str.endswith("Z"):
                            dt_str = dt_str[:-1] + "+00:00"
                        expiry = datetime.fromisoformat(dt_str)
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        if expiry <= now:
                            reason = "subscription expired"
                    except (ValueError, TypeError):
                        _log(f"User {user.email} has an invalid expiry date")
                if reason:
                    user.blocked = True
                    blocked_users[user.email] = reason
            if blocked_users:
                latest.install["sync_config_pending"] = True
            return blocked_users

        state, blocked = update_state(refresh_and_block)
        for email, reason in blocked.items():
            _log(f"User {email} blocked: {reason}")
            user = next((item for item in state.users if item.email == email), None)
            if user is None:
                continue
            for plugin in get_enabled(state):
                try:
                    plugin.on_user_block(user, state)
                except Exception as exc:
                    _log(f"Plugin {plugin.meta.name} block hook failed for {email}: {exc}")
                    failures.append(f"плагин {plugin.meta.name}: {exc}")

    else:
        _log("Sync: User limits check is disabled by settings")

    # 3. WARP: автообновление внешних списков (раз в 24 часа)
    if warp_enabled:
        try:
            from hydra.plugins.warp.plugin import WarpPlugin
            p = WarpPlugin()
            status = p.status()
            if status.enabled:
                # Проверяем кэш
                cache_file = WARP_CACHE_FILE
                need_update = force_all_checks or not cache_file.exists()
                if not need_update and cache_file.exists():
                    try:
                        import json
                        data = json.loads(cache_file.read_text(encoding="utf-8"))
                        up_str = data.get("updated_at")
                        if up_str:
                            updated_at = datetime.fromisoformat(up_str)
                            diff = datetime.now() - updated_at
                            if diff.total_seconds() < 86400:
                                need_update = False
                        elif data.get("last_attempt_at"):
                            attempted_at = datetime.fromisoformat(data["last_attempt_at"])
                            if (datetime.now() - attempted_at).total_seconds() < 3600:
                                need_update = False
                    except Exception:
                        pass

                if need_update:
                    check_kind = "manual" if force_all_checks else "scheduled"
                    _log(f"WARP: Triggering {check_kind} update of external rules...")
                    ok, msg = p.update_external_rules()
                    _log(f"WARP: Update result: {msg}")
                    if ok:
                        def mark_pending(latest):
                            latest.install["sync_config_pending"] = True

                        state, _ = update_state(mark_pending)
                        _log("WARP: Updated rules queued for config apply")
                    else:
                        failures.append(f"обновление WARP: {msg}")
                else:
                    _log("WARP: External rules cache is fresh; scheduled update skipped")
            else:
                _log("WARP: External rules update skipped because the plugin is disabled")
        except Exception as e:
            _log(f"WARP auto-update check failed: {e}")
            failures.append(f"проверка WARP: {e}")
    else:
        _log("Sync: WARP external rules auto-update is disabled by settings")

    # A pending apply may originate from limits, WARP or an earlier interrupted
    # run, so process all accumulated changes once and independently of toggles.
    if state.install.get("sync_config_pending"):
        from hydra.core.orchestrator import apply_config
        try:
            applied = apply_config(state)
        except Exception as exc:
            applied = False
            _log(f"Server config apply failed: {exc}")
        if applied:
            def clear_pending(latest):
                return latest.install.pop("sync_config_pending", None) is not None

            state, _ = update_state(clear_pending)
            _log("Applied pending server config")
        else:
            failures.append("не удалось применить конфигурацию сервера")
            _log("Server config apply failed; will retry on the next run")

    # 4. Sing-Box updates checking (раз в 24 часа или принудительно)
    if updates_enabled or force_update_check:
        try:
            from hydra.utils.downloader import latest_release
            from hydra.core.singbox import EXTENDED_REPO, get_version, parse_version

            last_check = state.install.get("singbox_last_update_check")
            need_check = True
            if not force_update_check and last_check:
                try:
                    last_dt = datetime.fromisoformat(last_check)
                    # Проверяем каждые 24 часа (86400 секунд)
                    if (datetime.now(timezone.utc) - last_dt).total_seconds() < 86400:
                        need_check = False
                except Exception:
                    pass

            if need_check:
                _log("Sing-Box Update: Checking for updates...")
                latest_ver = latest_release(EXTENDED_REPO)
                if latest_ver and latest_ver != "unknown":
                    current_ver = get_version()
                    
                    curr_parsed = parse_version(current_ver)
                    late_parsed = parse_version(latest_ver)
                    update_avail = late_parsed > curr_parsed
                    
                    _log(f"Sing-Box Update: Current version: {current_ver}, latest version on GitHub: {latest_ver}, update available: {update_avail}")

                    def save_update_info(latest):
                        latest.install["singbox_last_update_check"] = datetime.now(timezone.utc).isoformat()
                        latest.install["singbox_update_available"] = update_avail
                        latest.install["singbox_latest_version"] = latest_ver
                        return True

                    state, _ = update_state(save_update_info)
                else:
                    _log("Sing-Box Update: Failed to get latest version from GitHub")
                    failures.append("не удалось получить последнюю версию Sing-Box")
        except Exception as e:
            _log(f"Sing-Box Update: Update check failed: {e}")
            failures.append(f"проверка обновления Sing-Box: {e}")
    else:
        _log("Sync: Sing-Box update check is disabled by settings")

    pending = bool(state.install.get("sync_config_pending"))
    summary = (
        f"Sync completed: newly blocked users={len(blocked)}, "
        f"config pending={pending}, failures={len(failures)}"
    )
    _log(summary)
    if failures:
        return False, "; ".join(failures)
    return True, summary

def _log(msg: str) -> None:
    try:
        log = SYNC_LOG
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with log.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        run_sync()
    except Exception as e:
        _log(f"Sync failed: {e}")
        print(f"Sync agent error: {e}", file=sys.stderr)
        sys.exit(1)
