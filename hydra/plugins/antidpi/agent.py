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
from hydra.plugins.honeypot.plugin import HONEYPOT_LOG
from hydra.plugins.antidpi.adapters import parse_kernel_scan_line, parse_protocol_line, normalize_tls_auth_failure
from hydra.plugins.antidpi.plugin import (
    LOG_FILE,
    AntiDPIPlugin,
    normalize_caddy_record,
    normalize_decoy_record,
)

Normalized = tuple[str, dict]


def _offer_event(out: queue.Queue[Normalized], event: Normalized) -> None:
    """Keep collectors non-blocking under bursts, preferring recent evidence."""
    try:
        out.put_nowait(event)
        return
    except queue.Full:
        pass
    try:
        out.get_nowait()
    except queue.Empty:
        return
    try:
        out.put_nowait(event)
    except queue.Full:
        pass


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
            try:
                self._open()
            except OSError:
                return []
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



class TextTail(JsonTail):
    """Polling text tail for sources that do not emit JSON."""

    def __init__(self, path: Path, service: str):
        super().__init__(path, ())
        self.service = service

    def _open(self) -> None:
        # Protocol logs are owned by another service.  The hardened AntiDPI
        # unit must never create, touch, or replay them. Honeypot already bans
        # the first connection itself, so skipping a line during file creation
        # is safer than replaying historical CONNECT records.
        self.handle = self.path.open("r", encoding="utf-8", errors="replace")
        self.handle.seek(0, 2)
        self.inode = self.path.stat().st_ino

    def read(self) -> list[Normalized]:
        if self.handle is None:
            try:
                self._open()
            except OSError:
                return []
        try:
            stat = self.path.stat()
            if stat.st_ino != self.inode or stat.st_size < self.handle.tell():
                self.handle.close()
                self.handle = None
                self._open()
        except FileNotFoundError:
            return []
        except OSError:
            return []
        result = []
        while True:
            line = self.handle.readline()
            if not line:
                break
            event = parse_protocol_line(self.service, line)
            if event:
                event[1]["source"] = f"{self.service}-log"
                result.append(event)
        return result

def _journal_worker(out: queue.Queue[Normalized], stop: threading.Event) -> None:
    command = [
        "journalctl", "-f", "-n", "0", "-o", "json",
        "-u", "caddy-l4", "-u", "sing-box", "-u", "amneziawg",
        "-u", "hysteria2", "-u", "mieru", "-u", "snell", "-u", "telemt",
        "-u", "caddy-naive", "-u", "wdtt", "-u", "hydra-honeypot",
    ]
    while not stop.is_set():
        process = None
        try:
            process = HOST.popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, timeout=86400)
            assert process.stdout is not None
            for line in process.stdout:
                if stop.is_set():
                    break
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                event = parse_protocol_line(record.get("_SYSTEMD_UNIT", ""), record.get("MESSAGE", ""))
                if not event:
                    event = normalize_tls_auth_failure(record)
                if event:
                    _offer_event(out, event)
        except (OSError, RuntimeError):
            pass
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
        if not stop.wait(1):
            continue


def _kernel_worker(out: queue.Queue[Normalized], stop: threading.Event) -> None:
    command = ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]
    while not stop.is_set():
        process = None
        try:
            process = HOST.popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1, timeout=86400,
            )
            assert process.stdout is not None
            for line in process.stdout:
                if stop.is_set():
                    break
                event = parse_kernel_scan_line(line)
                if not event:
                    event = parse_protocol_line("kernel", line)
                if event:
                    _offer_event(out, event)
        except (OSError, RuntimeError):
            pass
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
        stop.wait(1)


def run() -> None:
    plugin = AntiDPIPlugin()
    events: queue.Queue[Normalized] = queue.Queue(maxsize=4096)
    stop = threading.Event()
    workers = (
        threading.Thread(target=_journal_worker, args=(events, stop), daemon=True),
        threading.Thread(target=_kernel_worker, args=(events, stop), daemon=True),
    )
    for worker in workers:
        worker.start()
    tails = (
        JsonTail(LOG_FILE, (normalize_caddy_record, normalize_tls_auth_failure)),
        JsonTail(DECOY_LOG, (normalize_decoy_record,)),
        TextTail(HONEYPOT_LOG, "honeypot"),
    )
    try:
        while True:
            for tail in tails:
                for event in tail.read():
                    _offer_event(events, event)
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
