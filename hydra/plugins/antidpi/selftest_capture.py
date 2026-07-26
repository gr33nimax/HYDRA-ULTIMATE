"""External AntiDPI capture helpers with injected host/state boundaries."""
from __future__ import annotations

import json
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.adapters import (
    decode_log_message,
    parse_kernel_scan_line,
    parse_protocol_line,
)
from hydra.plugins.antidpi.firewall_rules import (
    UDP_PROBE_CHAIN,
    udp_protocol_ports,
)


def all_journal(
    since: float,
    until: float,
    *,
    host,
    journal_units: dict[str, tuple[str, ...]],
) -> list[dict]:
    units = sorted(
        {
            "hydra-antidpi",
            "hydra-source-relay",
            "caddy-l4",
            "caddy-naive",
            *[
                unit
                for owners in journal_units.values()
                for unit in owners
            ],
        },
    )
    base = [
        "journalctl",
        "--no-pager",
        "-o",
        "json",
        f"--since=@{since:.3f}",
        f"--until=@{until:.3f}",
    ]
    command = list(base)
    for unit in units:
        command.extend(("-u", unit))
    records = []
    for journal_command in (command, [*base, "-k"]):
        result = host.run(
            journal_command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(record, dict):
                normalized = dict(record)
                normalized["MESSAGE"] = decode_log_message(
                    record.get("MESSAGE", ""),
                )
                records.append(normalized)
    return records


def all_new_log_lines(
    before: dict[Path, int],
) -> dict[str, list[str]]:
    result = {}
    for path, offset in before.items():
        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                if path.stat().st_size >= offset:
                    handle.seek(offset)
                lines = handle.read(8 * 1024 * 1024).splitlines()
        except OSError:
            lines = []
        if lines:
            result[str(path)] = lines[-50000:]
    return result


def udp_diagnostics(
    state: AppState,
    *,
    host,
    map_file: Path,
) -> dict:
    """Collect state needed to diagnose real UDP attribution and alerts."""
    commands = {
        "iptables_v4": ["iptables", "-S", UDP_PROBE_CHAIN],
        "iptables_v6": ["ip6tables", "-S", UDP_PROBE_CHAIN],
        "input_rules_v4": ["iptables", "-S", "INPUT"],
        "input_rules_v6": ["ip6tables", "-S", "INPUT"],
        "udp_sockets": ["ss", "-lunp"],
        "tcp_sockets": ["ss", "-ltnp"],
    }
    output = {}
    for label, command in commands.items():
        result = host.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output[label] = {
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[-100_000:],
            "stderr": (result.stderr or "")[-10_000:],
        }
    try:
        mappings = map_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()[-2000:]
    except OSError:
        mappings = []
    debug_control = Path("/proc/dynamic_debug/control")
    try:
        awg_debug = [
            line
            for line in debug_control.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if "amneziawg" in line
            or any(
                name in line
                for name in (
                    "prepare_awg_message",
                    "wg_receive_handshake_packet",
                    "wg_noise_handshake_consume_initiation",
                )
            )
        ][-500:]
    except OSError:
        awg_debug = []
    return {
        "protocol_ports": udp_protocol_ports(state),
        "commands": output,
        "source_relay_mappings": mappings,
        "amneziawg_dynamic_debug": awg_debug,
    }


def capture_event_summary(
    records: list[dict],
    state: AppState,
) -> list[dict]:
    """Summarize normalized evidence observed inside one capture window."""
    ports = udp_protocol_ports(state)
    counts: dict[tuple[str, str, str, str], int] = {}
    for record in records:
        message = decode_log_message(record.get("MESSAGE", ""))
        service = str(
            record.get("_SYSTEMD_UNIT", "")
            or record.get("SYSLOG_IDENTIFIER", ""),
        )
        event = parse_kernel_scan_line(message)
        if event and event[1].get("kind") == "udp_probe":
            try:
                destination_port = int(
                    event[1].get("destination_port", 0),
                )
            except (TypeError, ValueError):
                destination_port = 0
            event[1]["protocol"] = ports.get(destination_port, "udp")
        if not event:
            event = parse_protocol_line(service, message)
        if not event:
            continue
        address, details = event
        key = (
            address,
            str(details.get("protocol", "unknown")),
            str(details.get("kind", "unknown")),
            str(details.get("source", "unknown")),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "ip": ip,
            "protocol": protocol,
            "kind": kind,
            "source": source,
            "count": count,
        }
        for (ip, protocol, kind, source), count in sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]


def runtime_delta(before: dict, after: dict) -> dict:
    def scalar(name: str) -> int:
        return max(
            0,
            int(after.get(name, 0) or 0)
            - int(before.get(name, 0) or 0),
        )

    def counters(name: str) -> dict[str, int]:
        old = before.get(name, {}) if isinstance(before.get(name), dict) else {}
        new = after.get(name, {}) if isinstance(after.get(name), dict) else {}
        return {
            str(key): int(value or 0) - int(old.get(key, 0) or 0)
            for key, value in new.items()
            if int(value or 0) - int(old.get(key, 0) or 0) > 0
        }

    old_notifications = before.get("notification_stats", {})
    new_notifications = after.get("notification_stats", {})
    if not isinstance(old_notifications, dict):
        old_notifications = {}
    if not isinstance(new_notifications, dict):
        new_notifications = {}
    return {
        "events": scalar("events"),
        "sources": counters("source_counts"),
        "signals": counters("signal_counts"),
        "notifications": {
            key: max(
                0,
                int(new_notifications.get(key, 0) or 0)
                - int(old_notifications.get(key, 0) or 0),
            )
            for key in ("attempted", "delivered", "failed")
        },
    }


def write_capture_archive(
    archive: Path,
    *,
    report: dict,
    records: list[dict],
    logs: dict[str, list[str]],
    redact: Callable[[str], str],
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="hydra-antidpi-capture-",
    ) as temp_name:
        root = Path(temp_name) / "hydra-antidpi-capture"
        root.mkdir(parents=True)
        (root / "report.json").write_text(
            redact(json.dumps(report, ensure_ascii=False, indent=2)),
            encoding="utf-8",
        )
        (root / "journal.jsonl").write_text(
            redact(
                "\n".join(
                    json.dumps(item, ensure_ascii=False)
                    for item in records
                ),
            ),
            encoding="utf-8",
        )
        for index, (path, lines) in enumerate(logs.items(), 1):
            label = Path(path).name.replace(".", "-")
            (root / f"log-{index}-{label}.log").write_text(
                redact("\n".join(lines)),
                encoding="utf-8",
            )
        (root / "README.txt").write_text(
            "External AntiDPI capture. Runtime credentials are automatically "
            "redacted.\nReview the archive before sharing.\n",
            encoding="utf-8",
        )
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(root, arcname=root.name)
    archive.chmod(0o600)
