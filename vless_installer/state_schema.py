"""
Доступ к state.json HYDRA: подписки, пользователи, порты.

Единая точка для синхронизации users ↔ sub_tokens (делегирует user_lifecycle).
"""
from __future__ import annotations

import json
from pathlib import Path

STATE_FILE = Path("/var/lib/xray-installer/state.json")
DEFAULT_SUB_PORT = 9443


def load_state(*, migrate: bool = True) -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if migrate:
        from vless_installer.modules.user_lifecycle import migrate_state_users

        if migrate_state_users(state):
            save_state(state, migrate=False)
    return state


def save_state(state: dict, *, migrate: bool = True) -> None:
    if migrate:
        from vless_installer.modules.user_lifecycle import migrate_state_users

        migrate_state_users(state)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def get_sub_domain(state: dict | None = None) -> str:
    st = state if state is not None else load_state()
    return (st.get("sub_domain") or st.get("domain") or "").strip()


def get_sub_port(state: dict | None = None) -> int:
    st = state if state is not None else load_state()
    raw = st.get("sub_port", DEFAULT_SUB_PORT)
    try:
        port = int(raw)
        return port if 1 <= port <= 65535 else DEFAULT_SUB_PORT
    except (TypeError, ValueError):
        return DEFAULT_SUB_PORT


def set_sub_port(port: int, state: dict | None = None) -> dict:
    st = dict(state if state is not None else load_state())
    st["sub_port"] = int(port)
    save_state(st)
    return st


def set_sub_domain(domain: str, state: dict | None = None) -> dict:
    st = dict(state if state is not None else load_state())
    st["sub_domain"] = domain.strip()
    save_state(st)
    return st


def get_user_token(email: str, state: dict | None = None) -> str:
    st = state if state is not None else load_state()
    users = st.get("users", {})
    if isinstance(users.get(email), dict):
        tok = users[email].get("token")
        if tok:
            return str(tok)
    return str(st.get("sub_tokens", {}).get(email, "") or "")


def set_user_token(email: str, token: str, state: dict | None = None) -> dict:
    """Записывает токен в users[email].token и sub_tokens[email]."""
    st = dict(state if state is not None else load_state())
    users = st.setdefault("users", {})
    sub_tokens = st.setdefault("sub_tokens", {})

    row = users.get(email)
    if not isinstance(row, dict):
        from vless_installer.modules.user_lifecycle import _default_user_record

        row = _default_user_record(token)
        users[email] = row
    else:
        row["token"] = token

    sub_tokens[email] = token
    save_state(st)
    return st


def subscription_base_url(state: dict | None = None) -> str:
    """https://host[:port]/sub/<token> — порт только если не 443."""
    st = state if state is not None else load_state()
    domain = get_sub_domain(st) or "localhost"
    port = get_sub_port(st)
    if port in (443, 80):
        return f"https://{domain}"
    scheme = "https" if port != 80 else "http"
    return f"{scheme}://{domain}:{port}"
