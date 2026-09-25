"""Long-running anti-DPI collector for Caddy files and systemd journals."""

from __future__ import annotations

import json
import ipaddress
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.core.sni_router import DECOY_LOG, TRUSTTUNNEL_LOG, VLESS_CDN_DECOY_LOG
from hydra.plugins.antidpi.adapters import parse_protocol_line
from hydra.plugins.antidpi.detection import event_time as _event_now
from hydra.plugins.antidpi.normalization import normalize_decoy_record, normalize_vless_cdn_record
from hydra.plugins.antidpi.plugin import (
    CURSOR_FILE,
    AntiDPIPlugin,
)
from hydra.plugins.antidpi.paths import NAIVE_ACCESS_LOG
from hydra.plugins.antidpi.state_store import load_cursor, store_cursor

Normalizer = Callable[[dict], "tuple[str, dict] | None"]
Normalized = tuple[str, dict]
JournalRecord = tuple[Normalized | None, str]

RESTORE_INTERVAL = 600.0
HEARTBEAT_INTERVAL = 60.0
# Only protocols with a fixture-proven adapter are collected.  Sing-box serves
# Snell; generic TLS, kernel, UDP and unsupported transports are not observed
# at all, so they cannot become events, state or Telegram noise.
_JOURNAL_UNITS = ("sing-box",)


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


def _is_true(value: object) -> bool:
    """Return True only for the JSON boolean ``true``."""
    return isinstance(value, bool) and value


def _record_event_time(record: dict) -> float | None:
    """Return the record's own timestamp, when the format provides one."""
    for key in ("ts", "timestamp", "time"):
        value = record.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        try:
            seconds = float(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if seconds > 1_000_000_000_000:
            seconds /= 1000.0
        if seconds > 0:
            return seconds
    return None


def _journal_event_time(record: dict) -> float | None:
    try:
        microseconds = float(record.get("__REALTIME_TIMESTAMP", 0) or 0)
    except (TypeError, ValueError):
        return None
    return microseconds / 1_000_000.0 if microseconds > 0 else None


class JsonTail:
    """Polling JSONL tail that survives truncation and rename rotation."""

    def __init__(self, path: Path, normalizers: tuple, *, create: bool = True):
        self.path = path
        self.normalizers = normalizers if isinstance(normalizers, (list, tuple)) else (normalizers,)
        self.create = create
        self.handle: TextIO | None = None
        self.inode: int | None = None

    def _open(self, *, from_start: bool = False) -> None:
        if self.create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(exist_ok=True)
        handle = self.path.open("r", encoding="utf-8", errors="replace")
        # A fresh tail starts at the end (no history replay); a rotation
        # reopen starts at zero so already written events are not skipped.
        handle.seek(0, 0 if from_start else 2)
        self.handle = handle
        self.inode = self.path.stat().st_ino

    def _process_line(self, line: str) -> Normalized | None:
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            return None
        if not isinstance(record, dict):
            return None
        for norm in self.normalizers:
            try:
                normalized = norm(record)
            except (TypeError, ValueError):
                normalized = None
            if normalized:
                address, details = normalized
                event_time = _record_event_time(record)
                if event_time is not None:
                    details.setdefault("event_time", event_time)
                return address, details
        return None

    def read(self) -> list[Normalized]:
        if self.handle is None:
            try:
                self._open()
            except OSError:
                return []
        handle = self.handle
        if handle is None:
            return []
        try:
            stat = self.path.stat()
            if stat.st_ino != self.inode:
                handle.close()
                self.handle = None
                self._open(from_start=True)
                reopened = self.handle
                if reopened is None:
                    return []
                handle = reopened
            elif stat.st_size < handle.tell():
                # In-place truncation: reread from the start.
                handle.seek(0)
        except OSError:
            return []
        result = []
        while True:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.endswith("\n"):
                # Partial write: reread the whole line on the next poll.
                handle.seek(offset)
                break
            normalized = self._process_line(line)
            if normalized is not None:
                result.append(normalized)
        return result


def _journal_follow_command(cursor: str = "") -> list[str]:
    follow = ["journalctl", "-f"]
    if cursor:
        # Resume after the last seen record; downtime must not be skipped.
        follow += ["--after-cursor", cursor, "-o", "json"]
    else:
        follow += ["-n", "0", "-o", "json"]
    return [
        *follow,
        *(f"_SYSTEMD_UNIT={unit}.service" for unit in _JOURNAL_UNITS),
    ]


def _load_cursor() -> str:
    return load_cursor(CURSOR_FILE)


def _store_cursor(cursor: str) -> None:
    store_cursor(CURSOR_FILE, cursor)


def _normalize_journal_record(
    record: dict,
    state_reader: Callable[[], AppState],
) -> Normalized | None:
    del state_reader  # retained for the worker signature; no state is consulted
    message = str(record.get("MESSAGE", ""))
    unit = str(record.get("_SYSTEMD_UNIT", ""))
    event = parse_protocol_line(unit, message)
    if event and (event_time := _journal_event_time(record)) is not None:
        event[1].setdefault("event_time", event_time)
    return event


def _stop_journal_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _journal_worker(
    out: queue.Queue[JournalRecord],
    stop: threading.Event,
    state_reader: Callable[[], AppState],
    cursor_reader: Callable[[], str] | None = None,
) -> None:
    while not stop.is_set():
        cursor = (cursor_reader() if cursor_reader is not None else "") or _load_cursor()
        process = None
        records_read = 0
        try:
            process = HOST.popen(
                _journal_follow_command(cursor),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                timeout=86400,
            )
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
                records_read += 1
                fresh_cursor = str(record.get("__CURSOR", "")).strip()[:4096]
                event = _normalize_journal_record(record, state_reader)
                while not stop.is_set():
                    try:
                        out.put((event, fresh_cursor), timeout=0.25)
                        break
                    except queue.Full:
                        continue
        except (OSError, RuntimeError):
            pass
        finally:
            if process is not None:
                _stop_journal_process(process)
        if records_read == 0 and cursor and not stop.is_set():
            # An unresolvable cursor (rotation, vacuum) makes journalctl exit
            # immediately; drop it instead of restarting forever.
            cursor = ""
            _store_cursor("")
        if not stop.wait(1):
            continue


def _reconcile_enforcement(
    plugin: AntiDPIPlugin,
    state: AppState,
) -> bool:
    ok = plugin.reconcile_enforcement(state)
    if not ok:
        print(f"antidpi: {plugin.last_error}", file=sys.stderr)
    return ok


def run(
    plugin: AntiDPIPlugin,
    *,
    state_reader: Callable[[], AppState],
) -> None:
    """Run the collector with a plugin composed by an executable adapter."""
    try:
        initial_state = state_reader()
    except Exception:
        initial_state = AppState()
    if not _is_true(plugin.management_snapshot().get("degraded")):
        plugin.sync_host_whitelist(initial_state)
        plugin.cleanup_honeypot_duplicates()
    _reconcile_enforcement(plugin, initial_state)
    current_state = initial_state
    events: queue.Queue[Normalized] = queue.Queue(maxsize=4096)
    journal_events: queue.Queue[JournalRecord] = queue.Queue(maxsize=4096)
    stop = threading.Event()
    journal = threading.Thread(
        target=_journal_worker,
        args=(journal_events, stop, state_reader, plugin.journal_cursor),
        daemon=True,
    )
    journal.start()
    tails = (
        JsonTail(DECOY_LOG, (normalize_decoy_record,)),
        JsonTail(VLESS_CDN_DECOY_LOG, (normalize_vless_cdn_record,)),
        JsonTail(NAIVE_ACCESS_LOG, (normalize_decoy_record,), create=False),
        JsonTail(TRUSTTUNNEL_LOG, (normalize_decoy_record,)),
    )
    try:
        last_restore = time.monotonic()
        last_heartbeat = 0.0
        pending_journal: JournalRecord | None = None
        while True:
            if time.monotonic() - last_restore >= RESTORE_INTERVAL:
                # Heal drift between persisted bans and volatile ipset state.
                _reconcile_enforcement(plugin, current_state)
                last_restore = time.monotonic()
            if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL:
                plugin.record_collector_heartbeat()
                last_heartbeat = time.monotonic()
            for tail in tails:
                for event in tail.read():
                    _offer_event(events, event)
            while True:
                if pending_journal is None:
                    try:
                        pending_journal = journal_events.get_nowait()
                    except queue.Empty:
                        break
                record, cursor = pending_journal
                if record:
                    ip, event = record
                    event = {**event, "_journal_cursor": cursor}
                    plugin.observe_event(
                        ip,
                        event,
                        event_time=_event_now(event),
                    )
                    if cursor and plugin.journal_cursor() != cursor:
                        break
                if cursor:
                    _store_cursor(cursor)
                pending_journal = None
            while True:
                try:
                    ip, event = events.get_nowait()
                except queue.Empty:
                    break
                plugin.observe_event(
                    ip,
                    event,
                    event_time=_event_now(event),
                )
            time.sleep(0.25)
    finally:
        stop.set()
