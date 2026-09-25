"""Bounded maintenance for the traffic daemon's operator log."""
from __future__ import annotations

from pathlib import Path


TRAFFIC_LOG = Path("/var/log/hydra/traffic-daemon.log")
TRAFFIC_LOG_BACKUP = Path("/var/log/hydra/traffic-daemon.log.1")
TRAFFIC_LOG_MAX_BYTES = 5 * 1024 * 1024


def maintain_traffic_log(
    log: Path = TRAFFIC_LOG,
    backup: Path = TRAFFIC_LOG_BACKUP,
    max_bytes: int = TRAFFIC_LOG_MAX_BYTES,
) -> None:
    """Compact an oversized log while preserving its recent complete lines."""
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        if log.exists() and log.stat().st_size >= max_bytes:
            with log.open("rb") as handle:
                handle.seek(-min(log.stat().st_size, max_bytes), 2)
                tail = handle.read()
            newline = tail.find(b"\n")
            if newline >= 0:
                tail = tail[newline + 1 :]
            backup.write_bytes(tail)
            log.write_text("", encoding="utf-8")
    except OSError:
        pass


__all__ = [
    "TRAFFIC_LOG",
    "TRAFFIC_LOG_BACKUP",
    "TRAFFIC_LOG_MAX_BYTES",
    "maintain_traffic_log",
]
