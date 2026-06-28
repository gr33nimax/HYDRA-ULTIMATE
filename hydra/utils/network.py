"""
hydra/utils/network.py — Сетевые утилиты.
"""
import subprocess


def get_public_ip() -> str:
    """Возвращает публичный IPv4-адрес сервера."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
        ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
        ["hostname", "-I"],
    ):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
            )
            ip = r.stdout.strip().split()[0] if r.stdout.strip() else ""
            if ip and not ip.startswith("127.") and not ip.startswith("::"):
                return ip
        except Exception:
            continue
    return "0.0.0.0"


def command_exists(cmd: str) -> bool:
    """Проверяет, доступна ли команда."""
    import shutil
    return shutil.which(cmd) is not None
