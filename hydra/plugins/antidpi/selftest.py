"""Safe native-protocol probes and a redacted AntiDPI diagnostic bundle."""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import ssl
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from hydra import __version__
from hydra.core.host import HOST
from hydra.core.sni_router import DECOY_LOG, get_effective_port
from hydra.core.state import AppState
from hydra.plugins.antidpi.adapters import parse_protocol_line
from hydra.plugins.antidpi.agent import NAIVE_ACCESS_LOG

SUPPORTED_PROTOCOLS = (
    "amneziawg", "anytls", "trusttunnel", "shadowtls", "hysteria2",
    "mieru", "naive", "snell", "telemt", "wdtt",
)
JOURNAL_UNITS = {
    "amneziawg": ("amneziawg",),
    "anytls": ("sing-box",),
    "trusttunnel": ("sing-box",),
    "shadowtls": ("sing-box",),
    "hysteria2": ("sing-box", "hysteria2"),
    "mieru": ("sing-box", "mieru"),
    "naive": ("caddy-naive", "caddy-l4"),
    "snell": ("sing-box", "snell"),
    "telemt": ("telemt",),
    "wdtt": ("wdtt",),
}
LOG_PATHS = (DECOY_LOG, NAIVE_ACCESS_LOG, Path("/var/log/caddy-l4/antidpi.jsonl"))
_PAYLOADS = (
    b"HYDRA-ANTIDPI-SELFTEST\r\n",
    b"GET /__hydra_antidpi_selftest__ HTTP/1.1\r\nHost: invalid.local\r\nConnection: close\r\n\r\n",
    b"\x16\x03\x03\x00\x08INVALID!",
    b"\x00\xff\x00\xffHYDRA-INVALID-HANDSHAKE",
)


def _is_linux_host() -> bool:
    return os.name == "posix" and Path("/proc").exists()


def _environment() -> dict:
    units = sorted({"hydra-antidpi", "caddy-l4", *[unit for units in JOURNAL_UNITS.values() for unit in units]})
    services = {}
    for unit in units:
        result = HOST.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        services[unit] = result.stdout.strip() or "unknown"
    return {
        "hydra_version": __version__,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "services": services,
    }


@dataclass(frozen=True)
class Target:
    transport: str
    port: int
    host: str = "127.0.0.1"
    sni: str = ""


def _targets(state: AppState, protocol: str) -> list[Target]:
    ps = state.protocols.get(protocol)
    cfg = ps.config if ps else {}
    if protocol == "amneziawg":
        ports = []
        for profile in cfg.get("profiles", {}).values():
            if isinstance(profile, dict) and profile.get("port"):
                ports.append(int(profile["port"]))
        if not ports:
            ports.append(int(ps.port if ps and ps.port else 51820))
        return [Target("udp", port) for port in sorted(set(ports))]
    if protocol == "hysteria2":
        return [Target("udp", int(cfg.get("port", ps.port if ps and ps.port else 8443)))]
    if protocol == "wdtt":
        return [Target("udp", int(cfg.get("dtls_port", 56000)))]
    if protocol == "mieru":
        return [Target("tcp", int(ps.port if ps and ps.port else 2012))]
    if protocol == "snell":
        ports = {
            int(user.credentials.get("snell", {}).get("port", 0))
            for user in state.users if not user.blocked
        }
        ports.discard(0)
        return [Target("tcp", port) for port in sorted(ports)[:3]]
    if protocol == "telemt":
        return [Target("tcp", int(cfg.get("port", ps.port if ps and ps.port else 8443)))]
    if protocol == "trusttunnel" and str(cfg.get("transport", "tcp")) in {"quic", "both"}:
        port = get_effective_port(protocol, state)
        targets = [Target("udp", port)]
        if cfg.get("transport") == "both":
            targets.append(Target("tcp", port))
        return targets
    if protocol in {"anytls", "trusttunnel", "shadowtls", "naive"}:
        port = get_effective_port(protocol, state)
        domain = str(cfg.get("domain", "")).strip()
        # The internal listener exercises the native parser. The SNI frontend
        # additionally checks routing when a domain is configured.
        result = [Target("tcp", port)]
        if domain and port != 443:
            result.append(Target("tls", 443, sni=domain))
        return result
    return []


def _probe(target: Target, timeout: float = 0.8) -> list[dict]:
    results = []
    for payload in _PAYLOADS:
        started = time.monotonic()
        error = ""
        try:
            if target.transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(payload, (target.host, target.port))
            else:
                with socket.create_connection((target.host, target.port), timeout=timeout) as raw:
                    stream = raw
                    if target.transport == "tls":
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        stream = context.wrap_socket(raw, server_hostname=target.sni)
                    stream.sendall(payload)
                    try:
                        stream.recv(256)
                    except (OSError, TimeoutError):
                        pass
        except (OSError, ssl.SSLError) as exc:
            error = f"{exc.__class__.__name__}: {exc}"
        results.append({
            "transport": target.transport,
            "host": target.host,
            "port": target.port,
            "sni": target.sni,
            "payload_bytes": len(payload),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "error": error,
        })
    return results


def _journal(protocol: str, since: float, until: float) -> list[dict]:
    base = ["journalctl", "--no-pager", "-o", "json", f"--since=@{since:.3f}", f"--until=@{until:.3f}"]
    command = list(base)
    for unit in JOURNAL_UNITS[protocol]:
        command.extend(("-u", unit))
    records = []
    commands = [command]
    # WireGuard/AmneziaWG diagnostics are kernel messages, not records owned
    # by a conventional systemd service.
    if protocol == "amneziawg":
        commands.append([*base, "-k"])
    for journal_command in commands:
        result = HOST.run(journal_command, capture_output=True, text=True, timeout=15, check=False)
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def _offsets() -> dict[Path, int]:
    result = {}
    for path in LOG_PATHS:
        try:
            result[path] = path.stat().st_size
        except OSError:
            result[path] = 0
    return result


def _new_log_lines(before: dict[Path, int]) -> dict[str, list[str]]:
    result = {}
    for path, offset in before.items():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                if path.stat().st_size >= offset:
                    handle.seek(offset)
                lines = handle.read().splitlines()
        except OSError:
            lines = []
        if lines:
            result[str(path)] = lines
    return result


def _secret_values(state: AppState) -> set[str]:
    secrets: set[str] = set()
    sensitive = re.compile(r"pass|token|secret|private|psk|uuid|key", re.IGNORECASE)

    def visit(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key))
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child, key)
        elif sensitive.search(key) and isinstance(value, str) and len(value) >= 6:
            secrets.add(value)

    visit(asdict(state))
    return secrets


def _redactor(state: AppState) -> Callable[[str], str]:
    secrets = sorted(_secret_values(state), key=len, reverse=True)
    substitutions = (
        (re.compile(r"(?i)(authorization\s*[:=]\s*)(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"(?i)((?:password|passwd|token|secret|private_key|psk)\s*[:=]\s*)[^\s,}\]]+"), r"\1[REDACTED]"),
        (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1[REDACTED]@"),
    )

    def redact(text: str) -> str:
        result = str(text)
        for secret in secrets:
            result = result.replace(secret, "[REDACTED]")
        for pattern, replacement in substitutions:
            result = pattern.sub(replacement, result)
        return result

    return redact


def _record_summary(protocol: str, records: list[dict]) -> dict:
    messages = [str(record.get("MESSAGE", "")) for record in records if record.get("MESSAGE")]
    native_matches = []
    contextual_matches = []
    for record, message in zip((r for r in records if r.get("MESSAGE")), messages):
        unit = str(record.get("_SYSTEMD_UNIT", ""))
        if match := parse_protocol_line(unit, message):
            native_matches.append({"unit": unit, "ip": match[0], "event": match[1]})
        if match := parse_protocol_line(protocol, message):
            contextual_matches.append({"unit": unit, "ip": match[0], "event": match[1]})
    return {
        "journal_records": len(records),
        "journal_messages": len(messages),
        "current_filter_matches": native_matches,
        "protocol_context_matches": contextual_matches,
    }


def run_selftest(state: AppState, output: str | None = None, wait_seconds: float = 2.0) -> dict:
    """Probe enabled transports and write a redacted, support-friendly archive."""
    if not _is_linux_host():
        raise RuntimeError("AntiDPI selftest must run on the HYDRA Linux host")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = Path(output) if output else Path(f"/tmp/hydra-antidpi-selftest-{stamp}.tar.gz")
    if archive.is_dir():
        archive = archive / f"hydra-antidpi-selftest-{stamp}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    redact = _redactor(state)
    report: dict[str, object] = {
        "schema": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "safe_local_test": True,
        "warning": "Loopback probes test native logging and filters; they intentionally do not test firewall bans or Telegram.",
        "environment": _environment(),
        "protocols": {},
    }
    raw: dict[str, dict[str, object]] = {}
    for protocol in SUPPORTED_PROTOCOLS:
        ps = state.protocols.get(protocol)
        enabled = bool(ps and ps.enabled)
        item: dict[str, object] = {"enabled": enabled, "targets": [], "probes": [], "logs": {}}
        report["protocols"][protocol] = item
        if not enabled:
            item["status"] = "skipped_disabled"
            continue
        targets = _targets(state, protocol)
        item["targets"] = [asdict(target) for target in targets]
        if not targets:
            item["status"] = "skipped_no_target"
            continue
        before = _offsets()
        since = time.time() - 0.05
        for target in targets:
            item["probes"].extend(_probe(target))
        time.sleep(max(0.0, min(float(wait_seconds), 10.0)))
        until = time.time() + 0.05
        records = _journal(protocol, since, until)
        logs = _new_log_lines(before)
        item.update(_record_summary(protocol, records))
        item["logs"] = {path: len(lines) for path, lines in logs.items()}
        item["status"] = "captured" if records or logs else "no_native_log_output"
        raw[protocol] = {"journal": records, "logs": logs}

    with tempfile.TemporaryDirectory(prefix="hydra-antidpi-selftest-") as temp_name:
        root = Path(temp_name) / "hydra-antidpi-selftest"
        (root / "journal").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "report.json").write_text(redact(json.dumps(report, ensure_ascii=False, indent=2)), encoding="utf-8")
        (root / "README.txt").write_text(
            "HYDRA AntiDPI native self-test\n"
            "Safe local malformed connections only; no credentials were changed.\n"
            "The bundle is automatically redacted, but review it before sharing.\n",
            encoding="utf-8",
        )
        for protocol, captured in raw.items():
            journal_text = "\n".join(json.dumps(record, ensure_ascii=False) for record in captured["journal"])
            (root / "journal" / f"{protocol}.jsonl").write_text(redact(journal_text), encoding="utf-8")
            for index, (path, lines) in enumerate(captured["logs"].items(), 1):
                label = Path(path).name.replace(".", "-")
                (root / "logs" / f"{protocol}-{index}-{label}.log").write_text(
                    redact("\n".join(lines)), encoding="utf-8",
                )
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(root, arcname=root.name)
    archive.chmod(0o600)
    captured = sum(1 for item in report["protocols"].values() if item.get("status") == "captured")
    return {"ok": True, "archive": str(archive), "captured_protocols": captured, "report": report}
