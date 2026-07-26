"""Console adapter and compatibility surface for Telemt statistics."""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime

from hydra.core.host import HOST

from . import mtproto_stats_model as _model
from . import mtproto_stats_runtime as _runtime
from .mtproto_stats_model import (
    CHAIN_IN,
    CHAIN_OUT,
    CONFIG_FILE,
    CRON_FILE,
    SERVICE_NAME,
    STATS_FILE,
)

_RE_BYTES = re.compile(
    r"(?:rx|bytes_in)[=:\s]+(\d+).*?(?:tx|bytes_out)[=:\s]+(\d+)",
    re.IGNORECASE,
)

class _Cancelled(Exception):
    pass


def _run(cmd, capture=False, check=False):
    kwargs = {"check": check}
    if capture:
        kwargs.update(
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return HOST.run(cmd, **kwargs)


def _fmt_bytes(value):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024:
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value:.1f} PiB"


def _now_str() -> str:
    return _model.now_string()


def _today() -> str:
    return _model.today()


def _get_port() -> int:
    if not CONFIG_FILE.exists():
        return 8443
    match = re.search(
        r"^port\s*=\s*(\d+)",
        CONFIG_FILE.read_text(),
        re.MULTILINE,
    )
    return int(match.group(1)) if match else 8443


def _load_users() -> dict:
    users: dict = {}
    if not CONFIG_FILE.exists():
        return users
    in_section = False
    for line in CONFIG_FILE.read_text().splitlines():
        if line.strip() == "[access.users]":
            in_section = True
            continue
        if in_section and line.strip().startswith("["):
            break
        if in_section:
            match = re.match(
                r'^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=\s*"([a-f0-9]{32})"',
                line,
            )
            if match:
                users[match.group(1)] = match.group(2)
    return users


def _ipt_chain_exists(chain: str) -> bool:
    return _runtime.chain_exists(chain, _run)


def setup_iptables_accounting(port: int) -> None:
    _runtime.setup_accounting(port, run=_run, cron_file=CRON_FILE)


def _read_chain_bytes(chain: str) -> int:
    return _runtime.read_chain_bytes(chain, _run)


def _reset_accounting() -> None:
    _runtime.reset_accounting(_run)


def reset_accounting() -> None:
    _reset_accounting()


def _accounting_active() -> bool:
    return _ipt_chain_exists(CHAIN_IN) and _ipt_chain_exists(CHAIN_OUT)


def _parse_journal(since: str | None = None) -> dict:
    return _runtime.parse_journal(_run, since)


def _get_username_to_email_map(state=None) -> dict:
    mapping = {}
    try:
        from hydra.utils.crypto import derive_key

        for user in state.users if state is not None else ():
            mapping["u" + derive_key("telemt-user", user.uuid)[:8]] = user.email
    except Exception:
        pass
    return mapping


def _load_stats() -> dict:
    return _model.load_stats(STATS_FILE)


def _save_stats(data: dict) -> None:
    _model.save_stats(data, STATS_FILE)


def _collect(data: dict) -> dict:
    return _runtime.collect(
        data,
        read_bytes=_read_chain_bytes,
        journal=_parse_journal,
        configured_users=_load_users,
    )


def _render_stats(data: dict, realtime: bool = False, *, state=None) -> None:
    total = data.get("total", {})
    print("\n  TELEMT · СТАТИСТИКА")
    print(f"  Получено: {_fmt_bytes(total.get('rx', 0))}")
    print(f"  Отправлено: {_fmt_bytes(total.get('tx', 0))}")
    print(f"  Обновлено: {total.get('updated') or '—'}")
    print(f"  iptables accounting: {'активен' if data.get('ipt_ok') else 'не активен'}")
    users = data.get("users", {})
    mapping = _get_username_to_email_map(state)
    if users:
        print("\n  Пользователи:")
    for username, item in users.items():
        traffic = item.get("rx", 0) + item.get("tx", 0)
        print(
            f"  - {mapping.get(username, username)}: {_fmt_bytes(traffic)}, "
            f"сессий {item.get('sessions', 0)}, "
            f"последний вход {item.get('last_seen', '—')}"
        )
    if realtime:
        print(f"\n  {datetime.now():%H:%M:%S}")


def _refresh() -> dict:
    data = _collect(_load_stats())
    _save_stats(data)
    return data


def stats_menu(*, state=None) -> None:
    while True:
        data = _refresh()
        _render_stats(data, state=state)
        print("\n  [1] Обновить")
        print("  [2] Настроить iptables-учёт")
        print("  [3] Сбросить счётчики")
        print("  [Q] Назад")
        try:
            choice = input("  Выбор: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "2":
            setup_iptables_accounting(_get_port())
        elif choice == "3":
            reset_accounting()
        elif choice in ("q", ""):
            return


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Запустите от root.")
        raise SystemExit(1)
    stats_menu()
