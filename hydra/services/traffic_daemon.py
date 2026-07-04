"""
hydra/services/traffic_daemon.py — Фоновый демон учета трафика Sing-Box.
Опрашивает локальный Clash API и аккумулирует трафик в AppState.
"""
from __future__ import annotations

import json
import time
import sys
import urllib.request
import urllib.error
from pathlib import Path

from hydra.core.state import load_state, save_state

def run_daemon() -> None:
    def _log(msg: str) -> None:
        try:
            log_path = Path("/var/log/hydra/traffic-daemon.log")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{ts}] {msg}\n")
        except Exception:
            pass

    def _get_anytls_ports() -> dict[str, str]:
        import subprocess
        import re
        port_to_user = {}
        try:
            r = subprocess.run(
                ["journalctl", "-u", "sing-box", "-n", "1000", "--no-pager"],
                capture_output=True, text=True, timeout=3
            )
            if r.returncode == 0:
                id_to_port = {}
                id_to_user = {}
                for line in r.stdout.splitlines():
                    if "inbound/anytls" not in line:
                        continue
                    
                    match_id = re.search(r"INFO\s+\[(\d+)\s+[^\]]+\]", line)
                    if not match_id:
                        continue
                    conn_id = match_id.group(1)
                    
                    match_port = re.search(r"inbound connection from 127.0.0.1:(\d+)", line)
                    if match_port:
                        id_to_port[conn_id] = match_port.group(1)
                        continue
                    
                    match_user = re.search(r"inbound/anytls\[[^\]]+\]:\s+\[([^\]]+)\]\s+inbound connection to", line)
                    if match_user:
                        id_to_user[conn_id] = match_user.group(1)
                
                for cid, user in id_to_user.items():
                    if cid in id_to_port:
                        port_to_user[id_to_port[cid]] = user
        except Exception:
            pass
        return port_to_user

    def _get_trusttunnel_users() -> dict[str, str]:
        import subprocess
        import re
        id_to_user = {}
        try:
            r = subprocess.run(
                ["journalctl", "-u", "sing-box", "-n", "1000", "--no-pager"],
                capture_output=True, text=True, timeout=3
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "inbound/trusttunnel" not in line:
                        continue
                    
                    match_id = re.search(r"INFO\s+\[(\d+)\s+[^\]]+\]", line)
                    if not match_id:
                        continue
                    conn_id = match_id.group(1)
                    
                    match_user = re.search(r"inbound/trusttunnel\[[^\]]+\]:\s+\[([^\]]+)\]\s+inbound connection", line)
                    if match_user:
                        id_to_user[conn_id] = match_user.group(1)
        except Exception:
            pass
        return id_to_user

    _log("Traffic daemon started")

    active_connections: dict[str, dict] = {} # id -> {user, total}

    while True:
        try:
            state = load_state()
            if not getattr(state.network, "clash_api_enabled", False):
                time.sleep(15)
                continue

            port = getattr(state.network, "clash_api_port", 9090)
            secret = getattr(state.network, "clash_api_secret", "")

            # Делаем запрос к Clash API /connections
            url = f"http://127.0.0.1:{port}/connections"
            req = urllib.request.Request(url)
            if secret:
                req.add_header("Authorization", f"Bearer {secret}")

            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    body = response.read().decode("utf-8")
                    data = json.loads(body)
            except urllib.error.URLError:
                time.sleep(10)
                continue
            except Exception as e:
                _log(f"API query error: {e}")
                time.sleep(10)
                continue

            connections = data.get("connections", [])
            anytls_ports = _get_anytls_ports()
            trusttunnel_users = _get_trusttunnel_users()
            _log(f"DEBUG: anytls_ports count = {len(anytls_ports)}, trusttunnel_users count = {len(trusttunnel_users)}")

            if connections:
                _log(f"Raw first connection: {json.dumps(connections[0])}")
                summary = []
                for c in connections:
                    cid = c.get("id")
                    meta = c.get("metadata", {})
                    user = meta.get("user")
                    tag = meta.get("inboundTag") or meta.get("type", "")
                    sport = str(meta.get("sourcePort", ""))
                    if not user and "anytls" in tag:
                        user = anytls_ports.get(sport)
                    if not user and "trusttunnel" in tag:
                        user = trusttunnel_users.get(cid)
                    up = c.get("upload", 0)
                    down = c.get("download", 0)
                    summary.append(f"ID={cid}, User={user}, Tag={tag}, Rx={down}, Tx={up}")
                _log(f"Active connections summary: count={len(connections)}")

            current_ids = set()
            state_changed = False

            # Собираем дельты трафика по пользователям и протоколам
            deltas: dict[tuple[str, str], int] = {}

            for conn in connections:
                conn_id = conn.get("id")
                if not conn_id:
                    continue
                current_ids.add(conn_id)

                metadata = conn.get("metadata", {})
                email = metadata.get("user")
                
                # Определяем протокол по inboundTag или type
                inbound_tag = metadata.get("inboundTag", "") or metadata.get("type", "")
                if "anytls" in inbound_tag:
                    protocol = "anytls"
                elif "mieru" in inbound_tag:
                    protocol = "mieru"
                elif "trusttunnel" in inbound_tag:
                    protocol = "trusttunnel"
                else:
                    protocol = "unknown"

                if not email and protocol == "anytls":
                    sport = str(metadata.get("sourcePort", ""))
                    if sport in anytls_ports:
                        email = anytls_ports[sport]

                if not email and protocol == "trusttunnel":
                    email = trusttunnel_users.get(conn_id)

                if not email:
                    continue

                upload = conn.get("upload", 0)
                download = conn.get("download", 0)
                total = upload + download

                key = (email, protocol)

                if conn_id in active_connections:
                    old_total = active_connections[conn_id]["total"]
                    delta = total - old_total
                    if delta > 0:
                        deltas[key] = deltas.get(key, 0) + delta
                        active_connections[conn_id]["total"] = total
                else:
                    # Новое подключение
                    deltas[key] = deltas.get(key, 0) + total
                    active_connections[conn_id] = {
                        "user": email,
                        "total": total
                    }

            # Очищаем закрытые соединения из памяти
            closed_ids = set(active_connections.keys()) - current_ids
            for cid in closed_ids:
                active_connections.pop(cid, None)

            # Применяем накопленные дельты к AppState
            if deltas:
                for (email, protocol), delta in deltas.items():
                    for user in state.users:
                        if user.email == email:
                            user.traffic_used_bytes += delta
                            # Записываем в credentials по протоколам
                            if not isinstance(user.credentials, dict):
                                user.credentials = {}
                            proto_dict = user.credentials.setdefault(protocol, {})
                            proto_dict["traffic_used_bytes"] = proto_dict.get("traffic_used_bytes", 0) + delta
                            state_changed = True

            if state_changed:
                save_state(state)

        except Exception as e:
            _log(f"General error: {e}")

        time.sleep(5)

if __name__ == "__main__":
    try:
        run_daemon()
    except Exception as e:
        print(f"Traffic daemon fatal error: {e}", file=sys.stderr)
        sys.exit(1)
