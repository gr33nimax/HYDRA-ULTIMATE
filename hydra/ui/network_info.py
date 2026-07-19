"""Non-blocking network identity cache used by the TUI dashboard."""
from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NetworkSnapshot:
    public_ip: str
    country_flag: str
    dns: str
    fetched: bool


_lock = threading.Lock()
_public_ip = "Получение..."
_country_flag = ""
_fetched = False
_started = False


def _system_dns() -> str:
    resolv = Path("/etc/resolv.conf")
    try:
        for line in resolv.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


_dns = _system_dns()


def is_private_ip(value: str) -> bool:
    if not value or value == "127.0.0.1":
        return True
    parts = value.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    return (
        first in (10, 127)
        or (first == 192 and second == 168)
        or (first == 172 and 16 <= second <= 31)
    )


def _fetch() -> None:
    global _public_ip, _country_flag, _fetched
    public = "127.0.0.1"
    flag = ""
    try:
        from hydra.utils.net import public_ip
        public = public_ip()
        for url in ("https://ipinfo.io/country", "https://ipapi.co/country/"):
            try:
                result = subprocess.run(
                    ["curl", "-s", "--max-time", "3", url],
                    capture_output=True, text=True, timeout=4,
                )
                code = result.stdout.strip().upper()
                if len(code) == 2 and code.isalpha():
                    flag = "".join(chr(ord(char) + 127397) for char in code)
                    break
            except (OSError, subprocess.TimeoutExpired):
                continue
    except Exception:
        pass
    with _lock:
        _public_ip = public
        _country_flag = flag
        _fetched = True


def start() -> None:
    global _started, _public_ip
    with _lock:
        if _started:
            return
        _started = True
    try:
        from hydra.utils.net import local_ip
        local = local_ip()
        if local and not is_private_ip(local):
            with _lock:
                _public_ip = local
    except Exception:
        pass
    threading.Thread(target=_fetch, daemon=True, name="hydra-network-info").start()


def snapshot() -> NetworkSnapshot:
    with _lock:
        return NetworkSnapshot(_public_ip, _country_flag, _dns, _fetched)


if os.environ.get("HYDRA_DISABLE_BACKGROUND_PROBES") != "1":
    start()
