"""
vless_installer/modules/user_lifecycle.py
───────────────────────────────────────────────────────────────────────────────
Централизованное управление жизненным циклом пользователей во всех протоколах
(NaiveProxy, Mieru, AmneziaWG) и подсчет накопленного трафика.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

STATE_FILE = Path("/var/lib/xray-installer/state.json")
LOG_FILE = Path("/var/log/vless-install.log")
NAIVE_STATE = Path("/var/lib/xray-installer/naiveproxy.json")
MIERU_STATE = Path("/var/lib/xray-installer/mieru.json")

def _log(level: str, msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [LIFECYCLE] [{level}] {msg}\n")
    except Exception:
        pass

def _run(cmd: list, capture: bool = True, check: bool = False, quiet: bool = True) -> subprocess.CompletedProcess:
    kw = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


# ══════════════════════════════════════════════════════════════════════════════
#  ИЗМЕРЕНИЕ ЖИВОГО ТРАФИКА
# ══════════════════════════════════════════════════════════════════════════════

def get_naive_traffic_by_user() -> dict[str, int]:
    """Парсит /var/log/caddy-naive/access.log и суммирует байты по пользователям."""
    log_path = Path("/var/log/caddy-naive/access.log")
    if not log_path.exists():
        return {}
    
    traffic = {}
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    user = data.get("user_id")
                    if not user:
                        req = data.get("request", {})
                        user = req.get("user_id")
                    if user:
                        bytes_sent = int(data.get("size", 0))
                        bytes_recv = int(data.get("request", {}).get("size", 0))
                        traffic[user] = traffic.get(user, 0) + bytes_sent + bytes_recv
                except Exception:
                    continue
    except Exception as e:
        _log("ERROR", f"Error parsing Naive log: {e}")
    return traffic


def get_mieru_traffic_by_user() -> dict[str, int]:
    """Запрашивает журнал mita и возвращает трафик по пользователям Mieru."""
    traffic = {}
    try:
        from vless_installer.modules.mieru_stats import _parse_journal
        # Запрашиваем лог за последние 24 часа
        res = _parse_journal(window_minutes=1440)
        users = res.get("users", {})
        for uname, stats in users.items():
            dl = stats.get("download", 0)
            ul = stats.get("upload", 0)
            traffic[uname] = dl + ul
    except Exception as e:
        _log("ERROR", f"Error parsing Mieru journal: {e}")
    return traffic


def get_awg_traffic_all_users() -> dict[str, int]:
    """Считывает трафик по всем пользователям AmneziaWG из Docker."""
    traffic = {}
    try:
        from vless_installer.modules.amnezia_vpn import _get_container_name, _get_awg_interface_stats, _container_exists
        if not _container_exists():
            return {}
        name = _get_container_name()
        
        # Мапим clientId (pubkey) -> clientName
        key_to_name = {}
        r_srv = _run(["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"])
        if r_srv.returncode == 0:
            for cl in json.loads(r_srv.stdout):
                ud = cl.get("userData", {})
                cname = ud.get("clientName", "")
                if cname:
                    key_to_name[cl.get("clientId", "")] = cname.lower()
                    
        stats = _get_awg_interface_stats()
        for p in stats.get("peers", []):
            pubkey = p.get("public_key", "")
            friendly_name = key_to_name.get(pubkey)
            if friendly_name:
                rx = p.get("rx_bytes", 0)
                tx = p.get("tx_bytes", 0)
                traffic[friendly_name] = rx + tx
    except Exception as e:
        _log("ERROR", f"Error getting AWG traffic: {e}")
    return traffic


# ══════════════════════════════════════════════════════════════════════════════
#  НАКОПЛЕННЫЙ ТРАФИК И СБРОСЫ
# ══════════════════════════════════════════════════════════════════════════════

def get_user_cumulative_traffic(username: str, state: dict) -> int:
    """Вычисляет накопленный трафик пользователя во всех протоколах с защитой от сброса счетчиков."""
    users_db = state.setdefault("users", {})
    user_data = users_db.setdefault(username, {})
    
    # Складываем текущие значения из логов/служб
    np_bytes = get_naive_traffic_by_user().get(username, 0)
    mieru_bytes = get_mieru_traffic_by_user().get(username, 0)
    
    username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username).lower()
    awg_bytes = get_awg_traffic_all_users().get(username_clean, 0)
    
    current_live = np_bytes + mieru_bytes + awg_bytes
    
    baseline = user_data.setdefault("traffic_baseline", 0)
    accumulated = user_data.setdefault("traffic_accumulated", 0)
    
    if current_live < baseline:
        # Произошел сброс счетчиков (перезапуск докера, caddy или ротация логов)
        prev_live = user_data.get("previous_live", baseline)
        diff = max(0, prev_live - baseline)
        accumulated += diff
        baseline = 0
        user_data["traffic_baseline"] = baseline
        user_data["traffic_accumulated"] = accumulated
        
    user_data["previous_live"] = current_live
    total = accumulated + (current_live - baseline)
    return total


# ══════════════════════════════════════════════════════════════════════════════
#  ЖИЗНЕННЫЙ ЦИКЛ ПОЛЬЗОВАТЕЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════

def _default_user_record(token: str = "") -> dict:
    return {
        "token": token,
        "created_at": datetime.now().isoformat(),
        "expires_at": "",
        "limit_gb": 0,
        "is_blocked": False,
        "block_reason": "",
        "block_source": "",
        "traffic_baseline": 0,
        "traffic_accumulated": 0,
        "previous_live": 0,
        "creds": {},
    }


_AUTO_BLOCK_PREFIXES = (
    "Превышен лимит трафика",
    "Срок действия подписки истек",
    "Limit or TTL exceeded",
)


def _is_auto_block(user_data: dict) -> bool:
    """True если блокировка поставлена sync-agent (лимит/TTL), не админом."""
    source = str(user_data.get("block_source", "") or "")
    if source == "admin":
        return False
    if source == "auto":
        return True
    reason = str(user_data.get("block_reason", "") or "")
    return any(reason.startswith(p) for p in _AUTO_BLOCK_PREFIXES)


def _block_source_for_reason(reason: str) -> str:
    if "администратор" in reason.lower() or "вручную" in reason.lower():
        return "admin"
    if any(reason.startswith(p) for p in _AUTO_BLOCK_PREFIXES):
        return "auto"
    return "admin"


def migrate_state_users(state: dict) -> bool:
    """Синхронизирует sub_tokens → users и legacy blocked_users. Возвращает True если были изменения."""
    changed = False
    users_db = state.setdefault("users", {})
    sub_tokens = state.setdefault("sub_tokens", {})

    for email, token in list(sub_tokens.items()):
        if email not in users_db:
            users_db[email] = _default_user_record(str(token))
            changed = True
        else:
            u = users_db[email]
            if not u.get("token"):
                u["token"] = str(token)
                changed = True
            if "creds" not in u:
                u["creds"] = {}
                changed = True
        sub_tokens[email] = users_db[email].get("token") or str(token)

    for email, info in state.get("blocked_users", {}).items():
        if email not in users_db:
            users_db[email] = _default_user_record(sub_tokens.get(email, ""))
            changed = True
        if not users_db[email].get("is_blocked"):
            users_db[email]["is_blocked"] = True
            users_db[email]["block_reason"] = info.get("reason", "Blocked (legacy)")
            users_db[email]["block_source"] = "admin"
            changed = True
        elif not users_db[email].get("block_source"):
            users_db[email]["block_source"] = (
                "auto" if _is_auto_block(users_db[email]) else "admin"
            )
            changed = True

    return changed


def _load_state_migrated() -> dict:
    state = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    if migrate_state_users(state):
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    return state


def _save_state(state: dict) -> None:
    migrate_state_users(state)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def _capture_protocol_creds(username: str) -> dict:
    """Считывает пароли из naiveproxy.json / mieru.json до удаления пользователя."""
    creds: dict = {}
    try:
        if NAIVE_STATE.exists():
            for u in json.loads(NAIVE_STATE.read_text(encoding="utf-8")).get("users", []):
                if u.get("username") == username and u.get("password"):
                    creds["naive"] = {"password": u["password"]}
                    break
    except Exception as e:
        _log("WARN", f"capture naive creds for {username}: {e}")
    try:
        if MIERU_STATE.exists():
            for u in json.loads(MIERU_STATE.read_text(encoding="utf-8")).get("users", []):
                if u.get("username") == username and u.get("password"):
                    creds["mieru"] = {"password": u["password"]}
                    break
    except Exception as e:
        _log("WARN", f"capture mieru creds for {username}: {e}")
    return creds


def _merge_creds(user_data: dict, username: str) -> dict:
    creds = dict(user_data.get("creds") or {})
    for proto, data in _capture_protocol_creds(username).items():
        creds.setdefault(proto, data)
    return creds


def _provision_protocols(username: str, creds: Optional[dict] = None) -> dict:
    """Добавляет пользователя во все активные протоколы, восстанавливая сохранённые пароли."""
    creds = dict(creds or {})
    np_pass = creds.get("naive", {}).get("password")
    mieru_pass = creds.get("mieru", {}).get("password")

    try:
        from vless_installer.modules.naiveproxy import (
            add_user_noninteractive as np_add,
            restore_user_noninteractive as np_restore,
        )
        if np_pass:
            result = np_restore(username, np_pass)
        else:
            result = np_add(username)
        if result:
            creds.setdefault("naive", {})["password"] = result[1]
    except Exception as e:
        _log("ERROR", f"Failed to provision NaiveProxy for {username}: {e}")

    try:
        from vless_installer.modules.mieru import (
            add_user_noninteractive as mieru_add,
            restore_user_noninteractive as mieru_restore,
        )
        if mieru_pass:
            result = mieru_restore(username, mieru_pass)
        else:
            result = mieru_add(username)
        if result:
            creds.setdefault("mieru", {})["password"] = result[1]
    except Exception as e:
        _log("ERROR", f"Failed to provision Mieru for {username}: {e}")

    try:
        from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, ensure_awg_user
        if awg_exists():
            username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
            if username_clean:
                ensure_awg_user(username_clean)
    except Exception as e:
        _log("ERROR", f"Failed to provision AmneziaWG for {username}: {e}")

    return creds


def _deprovision_protocols(username: str) -> None:
    try:
        from vless_installer.modules.naiveproxy import delete_user_noninteractive as np_del
        np_del(username)
    except Exception as e:
        _log("ERROR", f"Failed to remove from NaiveProxy: {e}")

    try:
        from vless_installer.modules.mieru import delete_user_noninteractive as mieru_del
        mieru_del(username)
    except Exception as e:
        _log("ERROR", f"Failed to remove from Mieru: {e}")

    try:
        from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, _delete_client as awg_del
        if awg_exists():
            username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
            if username_clean:
                awg_del(username_clean)
    except Exception as e:
        _log("ERROR", f"Failed to remove from AmneziaWG: {e}")


def sync_user_lifecycle(username: str, action: str, reason: str = "") -> None:
    """
    Синхронизирует состояние пользователя во всех активных службах.
    Действия:
      - 'add': добавление во все протоколы и state.json
      - 'delete': полное удаление
      - 'block': отключение в VPN с сохранением creds в state.json
      - 'unblock': восстановление тех же creds во всех VPN
    """
    state = _load_state_migrated()
    users_db = state.setdefault("users", {})
    sub_tokens = state.setdefault("sub_tokens", {})

    _log("INFO", f"sync_user_lifecycle: username={username} action={action}")

    if action == "add":
        import uuid
        existing = users_db.get(username, {})
        token = existing.get("token") or sub_tokens.get(username) or str(uuid.uuid4())
        record = _default_user_record(token)
        for key in record:
            if key in existing and existing[key] not in ("", None, {}, []):
                record[key] = existing[key]
        record["token"] = token
        record["is_blocked"] = False
        record["block_reason"] = ""
        record["block_source"] = ""
        users_db[username] = record
        sub_tokens[username] = token
        state["users"] = users_db
        state["sub_tokens"] = sub_tokens
        _save_state(state)

        creds = _merge_creds(record, username)
        creds = _provision_protocols(username, creds) or creds
        record["creds"] = creds
        users_db[username] = record
        _save_state(state)

    elif action == "delete":
        if username in users_db:
            del users_db[username]
        if username in sub_tokens:
            del sub_tokens[username]
        blocked = state.get("blocked_users", {})
        if username in blocked:
            del blocked[username]
            state["blocked_users"] = blocked
        state["users"] = users_db
        state["sub_tokens"] = sub_tokens
        _save_state(state)
        _deprovision_protocols(username)

    elif action == "block":
        user_data = users_db.setdefault(username, _default_user_record(sub_tokens.get(username, "")))
        creds = _merge_creds(user_data, username)
        user_data["creds"] = creds
        user_data["is_blocked"] = True
        if not reason:
            reason = "Заблокирован администратором"
        user_data["block_reason"] = reason
        user_data["block_source"] = _block_source_for_reason(reason)
        users_db[username] = user_data
        sub_tokens[username] = user_data.get("token") or sub_tokens.get(username, "")
        state["users"] = users_db
        state["sub_tokens"] = sub_tokens
        _save_state(state)
        _deprovision_protocols(username)

    elif action == "unblock":
        user_data = users_db.get(username)
        if not user_data:
            sync_user_lifecycle(username, "add")
            return
        creds = _merge_creds(user_data, username)
        user_data["creds"] = creds
        user_data["is_blocked"] = False
        user_data["block_reason"] = ""
        user_data["block_source"] = ""
        user_data["traffic_baseline"] = user_data.get("previous_live", 0)
        user_data["traffic_accumulated"] = 0
        users_db[username] = user_data
        state["users"] = users_db
        _save_state(state)
        creds = _provision_protocols(username, creds) or creds
        user_data["creds"] = creds
        users_db[username] = user_data
        _save_state(state)


# ══════════════════════════════════════════════════════════════════════════════
#  ФОНОВАЯ СИНХРОНИЗАЦИЯ ЛИМИТОВ (SYNC AGENT)
# ══════════════════════════════════════════════════════════════════════════════

def check_and_sync_all_users_limits() -> None:
    """Выполняет проверку всех пользователей на лимиты трафика и TTL."""
    if not STATE_FILE.exists():
        return
        
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        migrate_state_users(state)
    except Exception as e:
        _log("ERROR", f"SyncAgent: Failed to read state.json: {e}")
        return
        
    users_db = state.get("users", {})
    if not users_db:
        return
        
    changed = False
    for username, user_data in list(users_db.items()):
        # 1. Считаем текущий накопленный трафик
        try:
            used_bytes = get_user_cumulative_traffic(username, state)
            user_data["used_bytes"] = used_bytes
            changed = True
        except Exception as e:
            _log("ERROR", f"SyncAgent: Failed to compute traffic for {username}: {e}")
            continue
            
        # 2. Проверяем лимит трафика
        limit_gb = user_data.get("limit_gb", 0)
        limit_bytes = limit_gb * 1024 ** 3 if limit_gb else 0
        
        # 3. Проверяем TTL лимит времени
        expires_at_str = user_data.get("expires_at", "")
        expired = False
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                now_val = datetime.now(expires_at.tzinfo) if expires_at.tzinfo is not None else datetime.now()
                if now_val > expires_at:
                    expired = True
            except Exception as e:
                _log("ERROR", f"SyncAgent: Invalid expires_at format for {username}: {e}")
                
        is_blocked = user_data.get("is_blocked", False)
        
        # Решение о блокировке/разблокировке
        should_block = False
        reason = ""
        if limit_bytes and used_bytes >= limit_bytes:
            should_block = True
            reason = f"Превышен лимит трафика ({used_bytes / 1024**3:.2f} GB / {limit_gb} GB)"
        elif expired:
            should_block = True
            reason = "Срок действия подписки истек"
            
        if should_block and not is_blocked:
            _log("INFO", f"SyncAgent: Blocking user {username}. Reason: {reason}")
            sync_user_lifecycle(username, "block", reason=reason)
            try:
                state = _load_state_migrated()
                users_db = state.get("users", {})
                changed = True
            except Exception:
                pass

            # Уведомление в Телеграм
            try:
                from vless_installer.modules.tg_bot import tg_notify_event
                tg_notify_event("traffic_limit", f"Пользователь <b>{username}</b> заблокирован. Причина: {reason}")
            except Exception:
                pass
                
        elif not should_block and is_blocked:
            if not _is_auto_block(user_data):
                continue
            # Пользователь был заблокирован автоматически, лимит увеличен или TTL продлён
            _log("INFO", f"SyncAgent: Unblocking user {username}")
            sync_user_lifecycle(username, "unblock")
            try:
                state = _load_state_migrated()
                users_db = state.get("users", {})
                changed = True
            except Exception:
                pass

            try:
                from vless_installer.modules.tg_bot import tg_notify_event
                tg_notify_event("traffic_limit", f"Пользователь <b>{username}</b> разблокирован.")
            except Exception:
                pass
                
    if changed:
        try:
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        except Exception as e:
            _log("ERROR", f"SyncAgent: Failed to save state.json: {e}")
