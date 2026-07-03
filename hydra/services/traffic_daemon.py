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
            if connections:
                summary = []
                for c in connections:
                    cid = c.get("id")
                    meta = c.get("metadata", {})
                    user = meta.get("user")
                    tag = meta.get("inboundTag")
                    up = c.get("upload", 0)
                    down = c.get("download", 0)
                    summary.append(f"ID={cid}, User={user}, Tag={tag}, Rx={down}, Tx={up}")
                _log(f"Active connections: {'; '.join(summary)}")

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
                if not email:
                    continue

                # Определяем протокол по inboundTag
                inbound_tag = metadata.get("inboundTag", "")
                protocol = "anytls" if "anytls" in inbound_tag else ("mieru" if "mieru" in inbound_tag else "unknown")

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
