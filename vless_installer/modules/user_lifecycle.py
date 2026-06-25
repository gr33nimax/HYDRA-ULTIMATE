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

STATE_FILE = Path("/var/lib/xray-installer/state.json")
LOG_FILE = Path("/var/log/vless-install.log")

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

def sync_user_lifecycle(username: str, action: str) -> None:
    """
    Синхронизирует состояние пользователя во всех активных службах.
    Действия:
      - 'add': добавление во все протоколы и state.json
      - 'delete': полное удаление
      - 'block': стирание доступов во всех VPN, но сохранение в state.json как заблокирован
      - 'unblock': восстановление доступов во всех VPN
    """
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    users_db = state.setdefault("users", {})
    sub_tokens = state.setdefault("sub_tokens", {})
    
    _log("INFO", f"sync_user_lifecycle: username={username} action={action}")
    
    if action == "add":
        token = users_db.get(username, {}).get("token") or sub_tokens.get(username)
        if not token:
            import uuid
            token = str(uuid.uuid4())
            
        users_db[username] = {
            "token": token,
            "created_at": users_db.get(username, {}).get("created_at") or datetime.now().isoformat(),
            "expires_at": users_db.get(username, {}).get("expires_at", ""),
            "limit_gb": users_db.get(username, {}).get("limit_gb", 0),
            "is_blocked": False,
            "block_reason": "",
            "traffic_baseline": 0,
            "traffic_accumulated": 0,
            "previous_live": 0,
        }
        sub_tokens[username] = token
        state["users"] = users_db
        state["sub_tokens"] = sub_tokens
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        
        # Провижнинг в протоколы
        try:
            from vless_installer.modules.naiveproxy import add_user_noninteractive as np_add
            np_add(username)
        except Exception as e:
            _log("ERROR", f"Failed to add to NaiveProxy: {e}")
            
        try:
            from vless_installer.modules.mieru import add_user_noninteractive as mieru_add
            mieru_add(username)
        except Exception as e:
            _log("ERROR", f"Failed to add to Mieru: {e}")
            
        try:
            from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, ensure_awg_user
            if awg_exists():
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
                if username_clean:
                    ensure_awg_user(username_clean)
        except Exception as e:
            _log("ERROR", f"Failed to add to AmneziaWG: {e}")

    elif action == "delete":
        if username in users_db:
            del users_db[username]
        if username in sub_tokens:
            del sub_tokens[username]
        state["users"] = users_db
        state["sub_tokens"] = sub_tokens
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        
        # Депровижнинг
        try:
            from vless_installer.modules.naiveproxy import delete_user_noninteractive as np_del
            np_del(username)
        except Exception as e:
            _log("ERROR", f"Failed to delete from NaiveProxy: {e}")
            
        try:
            from vless_installer.modules.mieru import delete_user_noninteractive as mieru_del
            mieru_del(username)
        except Exception as e:
            _log("ERROR", f"Failed to delete from Mieru: {e}")
            
        try:
            from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, _delete_client as awg_del
            if awg_exists():
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
                if username_clean:
                    awg_del(username_clean)
        except Exception as e:
            _log("ERROR", f"Failed to delete from AmneziaWG: {e}")

    elif action == "block":
        if username in users_db:
            users_db[username]["is_blocked"] = True
            users_db[username]["block_reason"] = "Limit or TTL exceeded"
            state["users"] = users_db
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            
        # Удаляем учетные записи из активных VPN
        try:
            from vless_installer.modules.naiveproxy import delete_user_noninteractive as np_del
            np_del(username)
        except Exception:
            pass
            
        try:
            from vless_installer.modules.mieru import delete_user_noninteractive as mieru_del
            mieru_del(username)
        except Exception:
            pass
            
        try:
            from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, _delete_client as awg_del
            if awg_exists():
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
                if username_clean:
                    awg_del(username_clean)
        except Exception:
            pass

    elif action == "unblock":
        if username in users_db:
            users_db[username]["is_blocked"] = False
            users_db[username]["block_reason"] = ""
            # При разблокировке сбрасываем live-базовую линию, чтобы отсчет начался с нуля
            users_db[username]["traffic_baseline"] = users_db[username].get("previous_live", 0)
            users_db[username]["traffic_accumulated"] = 0
            state["users"] = users_db
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            
        # Восстанавливаем учетные записи во всех VPN
        try:
            from vless_installer.modules.naiveproxy import add_user_noninteractive as np_add
            np_add(username)
        except Exception:
            pass
            
        try:
            from vless_installer.modules.mieru import add_user_noninteractive as mieru_add
            mieru_add(username)
        except Exception:
            pass
            
        try:
            from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists, ensure_awg_user
            if awg_exists():
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
                if username_clean:
                    ensure_awg_user(username_clean)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ФОНОВАЯ СИНХРОНИЗАЦИЯ ЛИМИТОВ (SYNC AGENT)
# ══════════════════════════════════════════════════════════════════════════════

def check_and_sync_all_users_limits() -> None:
    """Выполняет проверку всех пользователей на лимиты трафика и TTL."""
    if not STATE_FILE.exists():
        return
        
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
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
            sync_user_lifecycle(username, "block")
            # Снова читаем стейт, так как sync_user_lifecycle сохранил изменения
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            users_db = state.setdefault("users", {})
            user_data = users_db.setdefault(username, {})
            user_data["is_blocked"] = True
            user_data["block_reason"] = reason
            changed = True
            
            # Уведомление в Телеграм
            try:
                from vless_installer.modules.tg_bot import tg_notify_event
                tg_notify_event("traffic_limit", f"Пользователь <b>{username}</b> заблокирован. Причина: {reason}")
            except Exception:
                pass
                
        elif not should_block and is_blocked:
            # Пользователь был заблокирован, но теперь лимит увеличен или продлен TTL
            _log("INFO", f"SyncAgent: Unblocking user {username}")
            sync_user_lifecycle(username, "unblock")
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            users_db = state.setdefault("users", {})
            user_data = users_db.setdefault(username, {})
            user_data["is_blocked"] = False
            user_data["block_reason"] = ""
            changed = True
            
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
