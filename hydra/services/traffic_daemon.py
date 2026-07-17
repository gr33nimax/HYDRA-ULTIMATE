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

from hydra.core.state import AppState, load_state, update_state


def _apply_connection_snapshot(
    state: AppState,
    connections: list[dict],
    anytls_ports: dict[str, str],
    trusttunnel_users: dict[tuple[str, str], str | None],
    mieru_users: dict[tuple[str, str], str],
) -> bool:
    """Atomically apply connection deltas using counters persisted in AppState."""
    state.install["traffic_daemon_last_poll"] = time.time()
    active = state.install.setdefault("traffic_connection_counters", {})
    current_ids: set[str] = set()
    deltas: dict[tuple[str, str], int] = {}

    for connection in connections:
        connection_id = connection.get("id")
        if not connection_id:
            continue
        current_ids.add(connection_id)
        metadata = connection.get("metadata", {})
        user = metadata.get("user")
        inbound_tag = metadata.get("inboundTag", "") or metadata.get("type", "")
        if "anytls" in inbound_tag:
            protocol = "anytls"
            user = user or anytls_ports.get(str(metadata.get("sourcePort", "")))
        elif "trusttunnel" in inbound_tag:
            protocol = "trusttunnel"
            host = metadata.get("host") or metadata.get("destinationIP", "")
            user = user or trusttunnel_users.get(("__id__", str(connection_id)))
            user = user or trusttunnel_users.get((host.lower(), str(metadata.get("destinationPort", ""))))
        elif "mieru" in inbound_tag:
            protocol = "mieru"
            key = (metadata.get("sourceIP", "").lower(), str(metadata.get("sourcePort", "")))
            user = user or mieru_users.get(key)
        else:
            protocol = "unknown"

        upload = max(0, int(connection.get("upload", 0)))
        download = max(0, int(connection.get("download", 0)))
        total = upload + download
        previous = active.get(connection_id, {})
        old_total = int(previous.get("total", 0))
        if not user:
            user = previous.get("user") or ""
        if protocol == "unknown" and previous.get("protocol"):
            protocol = previous["protocol"]
        credited = int(previous.get(
            "credited_total", old_total if previous.get("user") else 0,
        ))
        if total < old_total:
            # A reused connection id or a reset runtime counter starts a new
            # accounting generation.
            credited = 0
        delta = max(0, total - credited) if user and protocol != "unknown" else 0
        active[connection_id] = {
            "user": user,
            "protocol": protocol,
            "total": total,
            "upload": upload,
            "download": download,
            "credited_total": total if delta else credited,
            "missed_polls": 0,
            "seen_at": time.time(),
        }
        if user and protocol != "unknown" and delta:
            key = (user, protocol)
            deltas[key] = deltas.get(key, 0) + delta

    # Keep a short tombstone window. A transiently incomplete API snapshot must
    # not erase the baseline and charge the full connection again, while short
    # sessions must not accumulate indefinitely in state.json.
    for connection_id in set(active) - current_ids:
        record = active[connection_id]
        record["missed_polls"] = int(record.get("missed_polls", 0)) + 1
        if record["missed_polls"] > 5:
            active.pop(connection_id, None)

    changed = bool(deltas)
    for (email, protocol), delta in deltas.items():
        for user in state.users:
            if user.email != email:
                continue
            user.traffic_used_bytes += delta
            protocol_stats = user.credentials.setdefault(protocol, {})
            protocol_stats["traffic_used_bytes"] = int(protocol_stats.get("traffic_used_bytes", 0)) + delta
            break
    return changed

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

    def _get_trusttunnel_users() -> dict[tuple[str, str], str | None]:
        import subprocess
        import re
        addr_to_user = {}
        try:
            r = subprocess.run(
                ["journalctl", "-u", "sing-box", "-n", "1000", "--no-pager"],
                capture_output=True, text=True, timeout=3
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "inbound/trusttunnel" not in line:
                        continue
                    
                    # Ищем имя пользователя и цель, например:
                    # [tester2] inbound connection to speedtest-nl.vdsina.ru:8080
                    m = re.search(
                        r"inbound/trusttunnel\[[^\]]+\]:\s+\[([^\]]+)\]\s+inbound connection to\s+([a-zA-Z0-9\-\._]+|\[[0-9a-fA-F:]+\]):(\d+)",
                        line
                    )
                    if m:
                        user = m.group(1)
                        host = m.group(2)
                        port = m.group(3)
                        key = (host.lower(), port)
                        match_id = re.search(r"INFO\s+\[(\d+)\s+[^\]]+\]", line)
                        if match_id:
                            addr_to_user[("__id__", match_id.group(1))] = user
                        previous = addr_to_user.get(key)
                        if previous is not None and previous != user:
                            # Destination-only attribution is ambiguous when
                            # multiple users access the same endpoint.
                            addr_to_user[key] = None
                        elif key not in addr_to_user:
                            addr_to_user[key] = user
        except Exception:
            pass
        return addr_to_user

    def _get_mieru_users() -> dict[tuple[str, str], str]:
        import subprocess
        import re
        conn_to_addr = {} # conn_id -> (ip, port)
        conn_to_user = {} # conn_id -> user
        addr_to_user = {} # (ip, port) -> user
        try:
            r = subprocess.run(
                ["journalctl", "-u", "sing-box", "-n", "1000", "--no-pager"],
                capture_output=True, text=True, timeout=3
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "inbound/mieru" not in line:
                        continue
                    
                    # 1. Ищем строку с адресом
                    m_addr = re.search(
                        r"INFO\s+\[(\d+)\s+[^\]]+\]\s+inbound/mieru\[[^\]]+\]:\s+inbound\s+(?:TCP|UDP)\s+connection\s+from\s+\[?([a-zA-Z0-9\-\.:]+)\]?:(\d+)",
                        line
                    )
                    if m_addr:
                        conn_id = m_addr.group(1)
                        ip = m_addr.group(2).lower()
                        port = m_addr.group(3)
                        conn_to_addr[conn_id] = (ip, port)
                        continue
                    
                    # 2. Ищем строку с юзером
                    m_user = re.search(
                        r"INFO\s+\[(\d+)\s+[^\]]+\]\s+inbound/mieru\[[^\]]+\]:\s+\[([^\]]+)\]\s+inbound\s+(?:TCP|UDP)\s+connection",
                        line
                    )
                    if m_user:
                        conn_id = m_user.group(1)
                        user = m_user.group(2)
                        conn_to_user[conn_id] = user
                
                # Сопоставляем
                for conn_id, user in conn_to_user.items():
                    if conn_id in conn_to_addr:
                        ip, port = conn_to_addr[conn_id]
                        addr_to_user[(ip, port)] = user
                        if ip.startswith("::ffff:"):
                            addr_to_user[(ip[7:], port)] = user
        except Exception:
            pass
        return addr_to_user

    _log("Traffic daemon started")

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
            mieru_users = _get_mieru_users()
            update_state(lambda latest: _apply_connection_snapshot(
                latest, connections, anytls_ports, trusttunnel_users, mieru_users,
            ))

        except Exception as e:
            _log(f"General error: {e}")

        time.sleep(2)

if __name__ == "__main__":
    try:
        run_daemon()
    except Exception as e:
        print(f"Traffic daemon fatal error: {e}", file=sys.stderr)
        sys.exit(1)
