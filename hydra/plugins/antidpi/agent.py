"""Long-running anti-DPI collector for Caddy files and systemd journals."""
from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.sni_router import DECOY_LOG
from hydra.plugins.antidpi.adapters import parse_protocol_line, normalize_tls_auth_failure
from hydra.plugins.antidpi.plugin import (
    LOG_FILE,
    AntiDPIPlugin,
    normalize_caddy_record,
    normalize_decoy_record,
)

Normalized = tuple[str, dict]


class JsonTail:
    """Polling JSONL tail that survives truncation and rename rotation."""
    def __init__(self, path: Path, normalizers: tuple):
        self.path = path
        self.normalizers = normalizers if isinstance(normalizers, (list, tuple)) else (normalizers,)
        self.handle = None
        self.inode = None

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.handle = self.path.open("r", encoding="utf-8", errors="replace")
        self.handle.seek(0, 2)
        self.inode = self.path.stat().st_ino

    def read(self) -> list[Normalized]:
        if self.handle is None:
            self._open()
        try:
            stat = self.path.stat()
            if stat.st_ino != self.inode or stat.st_size < self.handle.tell():
                self.handle.close()
                self.handle = None
                self._open()
        except OSError:
            return []
        result = []
        while True:
            line = self.handle.readline()
            if not line:
                break
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            for norm in self.normalizers:
                try:
                    normalized = norm(record)
                except (TypeError, ValueError):
                    normalized = None
                if normalized:
                    result.append(normalized)
                    break
        return result


def _journal_worker(out: queue.Queue[Normalized], stop: threading.Event) -> None:
    command = [
        "journalctl", "-f", "-n", "0", "-o", "json",
        "-u", "caddy-l4", "-u", "sing-box", "-u", "amneziawg",
        "-u", "hysteria2", "-u", "mieru", "-u", "snell", "-u", "telemt",
    ]
    while not stop.is_set():
        process = HOST.popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, timeout=86400)
        assert process.stdout is not None
        for line in process.stdout:
            if stop.is_set():
                break
            try:
                record = json.loads(line)
            except ValueError:
                continue
            event = parse_protocol_line(record.get("_SYSTEMD_UNIT", ""), record.get("MESSAGE", ""))
            if not event:
                event = normalize_tls_auth_failure(record)
            if event:
                out.put(event)
        process.terminate()
        if not stop.wait(1):
            continue


def run() -> None:
    plugin = AntiDPIPlugin()
    events: queue.Queue[Normalized] = queue.Queue(maxsize=4096)
    stop = threading.Event()
    worker = threading.Thread(target=_journal_worker, args=(events, stop), daemon=True)
    worker.start()
    tails = (
        JsonTail(LOG_FILE, (normalize_caddy_record, normalize_tls_auth_failure)),
        JsonTail(DECOY_LOG, (normalize_decoy_record,)),
    )
    try:
        while True:
            for tail in tails:
                for event in tail.read():
                    events.put(event)
            while True:
                try:
                    ip, event = events.get_nowait()
                except queue.Empty:
                    break
                plugin.observe_event(ip, event)
            time.sleep(0.25)
    finally:
        stop.set()


if __name__ == "__main__":
    run()
