"""
hydra/utils/logging.py — Логирование.
"""
from pathlib import Path
from datetime import datetime

LOG_DIR = Path("/var/log/hydra")
LOG_FILE = LOG_DIR / "install.log"


def log(level: str, msg: str) -> None:
    """Записывает сообщение в лог-файл."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass


def info(msg: str) -> None:
    log("INFO", msg)


def warn(msg: str) -> None:
    log("WARN", msg)


def error(msg: str) -> None:
    log("ERROR", msg)
