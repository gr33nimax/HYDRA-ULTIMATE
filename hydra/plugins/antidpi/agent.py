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

from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.core.sni_router import DECOY_LOG, TRUSTTUNNEL_LOG
from hydra.plugins.antidpi.adapters import (
    normalize_tls_auth_failure,
    parse_kernel_scan_line,
    parse_protocol_line,
    parse_unattributed_protocol_line,
)
from hydra.plugins.antidpi.detection import event_time as _event_now
from hydra.plugins.antidpi.normalization import (
    vless_endpoint,
    vless_normalizer,
)
from hydra.plugins.antidpi.plugin import (
    CURSOR_FILE,
    LOG_FILE,
    AntiDPIPlugin,
    normalize_caddy_record,
    normalize_decoy_record,
    normalize_naive_decoy_record,
    normalize_trusttunnel_record,
    udp_protocol_ports,
)
from hydra.plugins.antidpi.paths import NAIVE_ACCESS_LOG
from hydra.plugins.antidpi.state_store import load_cursor, store_cursor

Normalizer = Callable[[dict], "tuple[str, dict] | None"]
Normalized = tuple[str, dict]
JournalRecord = tuple[Normalized | None, str]
_udp_port_cache: tuple[float, dict[int, str]] = (0.0, {})

RESTORE_INTERVAL = 600.0
HEARTBEAT_INTERVAL = 60.0
_JOURNAL_UNITS = (
    "caddy-l4", "sing-box", "amneziawg", "hysteria2", "mieru",
    "snell", "telemt", "caddy-naive", "wdtt",
)


def _attribute_udp_protocol(
    event: Normalized | None,
    state_reader: Callable[[], AppState],
) -> Normalized | None:
    global _udp_port_cache
    if not event:
        return event
    address, details = event
    if details.get("kind") != "udp_probe":
        return event
    now = time.monotonic()
    if now - _udp_port_cache[0] > 10:
        try:
            _udp_port_cache = (now, udp_protocol_ports(state_reader()))
        except Exception:
            _udp_port_cache = (now, {})
    try:
        port = int(details.get("destination_port", 0))
    except (TypeError, ValueError):
        port = 0
    resolved = dict(details)
    resolved["protocol"] = _udp_port_cache[1].get(port, "udp")
    return address, resolved


def _resolve_relay_source(event: Normalized | None) -> Normalized | None:
    if not event:
        return event
    ip, details = event
    try:
        if not ipaddress.ip_address(ip).is_loopback:
            return event
        peer_port = int(details.get("peer_port", 0))
    except (TypeError, ValueError):
        return event
    if peer_port <= 0:
        return event
    from hydra.core.source_relay import resolve_mapping
    source = resolve_mapping(str(details.get("protocol", "")), peer_port)
    if not source:
        return event
    resolved = dict(details)
    resolved["source"] = "caddy-source-relay"
    resolved["relay_peer_port"] = peer_port
    return source, resolved


def _resolve_unattributed_relay_source(details: dict | None) -> Normalized | None:
    if not details:
        return None
    from hydra.core.source_relay import resolve_recent_unique_source
    source = resolve_recent_unique_source(str(details.get("protocol", "")))
    if not source:
        return None
    resolved = dict(details)
    resolved["source"] = "caddy-source-relay"
    resolved["attribution"] = "unique-recent-source"
    # No connection reference: the address is a time-window guess, so the
    # hint stays observability and can never enforce a ban by itself.
    resolved["ban_eligible"] = False
    resolved["policy"] = "alert-only / time-correlated attribution"
    return source, resolved


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


def _record_event_time(record: dict) -> float | None:
    """Return the record's own timestamp, when the format provides one."""
    for key in ("ts", "timestamp", "time"):
        value = record.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        seconds = float(value)
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
        self.handle = None
        self.inode = None

    def _open(self, *, from_start: bool = False) -> None:
        if self.create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(exist_ok=True)
        self.handle = self.path.open("r", encoding="utf-8", errors="replace")
        # A fresh tail starts at the end (no history replay); a rotation
        # reopen starts at zero so already written events are not skipped.
        self.handle.seek(0, 0 if from_start else 2)
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
        try:
            stat = self.path.stat()
            if stat.st_ino != self.inode:
                self.handle.close()
                self.handle = None
                self._open(from_start=True)
            elif stat.st_size < self.handle.tell():
                # In-place truncation: reread from the start.
                self.handle.seek(0)
        except OSError:
            return []
        result = []
        while True:
            offset = self.handle.tell()
            line = self.handle.readline()
            if not line:
                break
            if not line.endswith("\n"):
                # Partial write: reread the whole line on the next poll.
                self.handle.seek(offset)
                break
            normalized = self._process_line(line)
            if normalized is not None:
                result.append(normalized)
        return result


class TextTail(JsonTail):
    """Polling text tail for sources that do not emit JSON."""

    def __init__(self, path: Path, service: str):
        super().__init__(path, ())
        self.service = service

    def _open(self, *, from_start: bool = False) -> None:
        # Protocol logs belong to another service: never create or touch
        # them, and never replay their history on a fresh tail.
        self.handle = self.path.open("r", encoding="utf-8", errors="replace")
        self.handle.seek(0, 0 if from_start else 2)
        self.inode = self.path.stat().st_ino

    def _process_line(self, line: str) -> Normalized | None:
        event = parse_protocol_line(self.service, line)
        if event:
            event[1]["source"] = f"{self.service}-log"
            return event
        return None


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
        "+",
        "_TRANSPORT=kernel",
    ]


def _load_cursor() -> str:
    return load_cursor(CURSOR_FILE)


def _store_cursor(cursor: str) -> None:
    store_cursor(CURSOR_FILE, cursor)


def _normalize_journal_record(
    record: dict,
    state_reader: Callable[[], AppState],
) -> Normalized | None:
    message = str(record.get("MESSAGE", ""))
    if record.get("_TRANSPORT") == "kernel":
        event = parse_kernel_scan_line(message)
        event = _attribute_udp_protocol(event, state_reader)
        event = event or parse_protocol_line("kernel", message)
    else:
        unit = str(record.get("_SYSTEMD_UNIT", ""))
        event = parse_protocol_line(unit, message)
        if not event:
            event = normalize_tls_auth_failure(record)
        event = _resolve_relay_source(event)
        if not event:
            details = parse_unattributed_protocol_line(unit, message)
            event = _resolve_unattributed_relay_source(details)
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
            process = HOST.popen(_journal_follow_command(cursor), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, timeout=86400)
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


def _bind_vless_normalizer(
    tail: JsonTail,
    endpoint: tuple[str, tuple[str, ...]],
) -> None:
    """Point the shared decoy tail at the current VLESS domain and path.

    The path lives in plugin config, so the normalizer is rebound whenever
    the operator changes the domain, the path, or disables the transport.
    """
    domain, paths = endpoint
    normalizer = vless_normalizer(domain, paths)
    tail.normalizers = (
        (normalizer, normalize_decoy_record)
        if normalizer is not None
        else (normalize_decoy_record,)
    )


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
    if plugin.management_snapshot().get("degraded") is not True:
        plugin.sync_host_whitelist(initial_state)
        plugin.cleanup_honeypot_duplicates()
    _reconcile_enforcement(plugin, initial_state)
    synced_udp_ports = udp_protocol_ports(initial_state)
    current_state = initial_state
    initial_mieru = initial_state.protocols.get("mieru")
    synced_mieru_enabled = bool(initial_mieru and initial_mieru.enabled)
    events: queue.Queue[Normalized] = queue.Queue(maxsize=4096)
    journal_events: queue.Queue[JournalRecord] = queue.Queue(maxsize=4096)
    stop = threading.Event()
    journal = threading.Thread(
        target=_journal_worker,
        args=(journal_events, stop, state_reader, plugin.journal_cursor),
        daemon=True,
    )
    journal.start()
    decoy_tail = JsonTail(DECOY_LOG, (normalize_decoy_record,))
    synced_vless = vless_endpoint(initial_state)
    _bind_vless_normalizer(decoy_tail, synced_vless)
    tails = (
        JsonTail(LOG_FILE, (normalize_caddy_record, normalize_tls_auth_failure)),
        decoy_tail,
        JsonTail(NAIVE_ACCESS_LOG, (normalize_naive_decoy_record,), create=False),
        JsonTail(TRUSTTUNNEL_LOG, (normalize_trusttunnel_record,)),
    )
    try:
        last_udp_sync = time.monotonic()
        last_restore = time.monotonic()
        last_heartbeat = 0.0
        pending_journal: JournalRecord | None = None
        while True:
            if time.monotonic() - last_udp_sync >= 60:
                try:
                    current_state = state_reader()
                    current_udp_ports = udp_protocol_ports(current_state)
                    current_mieru = current_state.protocols.get("mieru")
                    current_mieru_enabled = bool(current_mieru and current_mieru.enabled)
                    current_vless = vless_endpoint(current_state)
                except Exception:
                    current_udp_ports = synced_udp_ports
                    current_mieru_enabled = synced_mieru_enabled
                    current_vless = synced_vless
                if current_vless != synced_vless:
                    _bind_vless_normalizer(decoy_tail, current_vless)
                    synced_vless = current_vless
                # Recreating hashlimit rules clears their counters. Refresh
                # only when listener ports changed so sustained silent UDP
                # rejects can cross the telemetry threshold.
                if current_udp_ports != synced_udp_ports and plugin.sync_udp_probe_rules():
                    synced_udp_ports = current_udp_ports
                if (
                    current_mieru_enabled != synced_mieru_enabled
                    and plugin.sync_mieru_probe_rules(current_state)
                ):
                    synced_mieru_enabled = current_mieru_enabled
                last_udp_sync = time.monotonic()
            if time.monotonic() - last_restore >= RESTORE_INTERVAL:
                # Heal drift between persisted bans and volatile ipset state.
                _reconcile_enforcement(plugin, current_state)
                last_restore = time.monotonic()
            if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL:
                plugin.record_collector_heartbeat()
                last_heartbeat = time.monotonic()
            for tail in tails:
                for event in tail.read():
                    resolved = _resolve_relay_source(event)
                    if resolved:
                        _offer_event(events, resolved)
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
