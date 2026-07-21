"""Safe native-protocol probes and a redacted AntiDPI diagnostic bundle."""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
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
from hydra.plugins.antidpi.adapters import decode_log_message, parse_protocol_line
from hydra.plugins.antidpi.agent import NAIVE_ACCESS_LOG

SUPPORTED_PROTOCOLS = (
    "amneziawg", "anytls", "trusttunnel", "shadowtls", "hysteria2",
    "mieru", "naive", "snell", "telemt", "wdtt",
)
SINGBOX_CLIENT_PROTOCOLS = {
    "anytls", "trusttunnel", "shadowtls", "hysteria2", "mieru", "naive", "snell",
}
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
    b"CONNECT selftest.invalid:443 HTTP/1.1\r\nHost: selftest.invalid:443\r\n"
    b"Proxy-Authorization: Basic aW52YWxpZDppbnZhbGlk\r\nConnection: close\r\n\r\n",
    b"\x16\x03\x03\x00\x08INVALID!",
    b"\x00\xff\x00\xffHYDRA-INVALID-HANDSHAKE",
)


def _is_linux_host() -> bool:
    return os.name == "posix" and Path("/proc").exists()


def _environment() -> dict:
    units = sorted({
        "hydra-antidpi", "hydra-awg-antidpi-debug", "caddy-l4",
        *[unit for units in JOURNAL_UNITS.values() for unit in units],
    })
    services = {}
    for unit in units:
        result = HOST.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        services[unit] = result.stdout.strip() or "unknown"
    binaries = {}
    for name in ("sing-box", "awg", "caddy-l4", "caddy-naive"):
        executable = HOST.which(name)
        if not executable:
            continue
        result = HOST.run([executable, "version"], capture_output=True, text=True, timeout=5)
        output = (result.stdout or result.stderr or "").strip().splitlines()
        binaries[name] = " | ".join(output[:3])[:500] if output else "unknown"
    return {
        "hydra_version": __version__,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "services": services,
        "binaries": binaries,
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
        domain = str(cfg.get("domain", state.network.domain if protocol == "naive" else "")).strip()
        # The internal listener exercises the native parser. The SNI frontend
        # additionally checks routing when a domain is configured.
        mode = str(cfg.get("network", "tcp")) if protocol == "naive" else "tcp"
        result = []
        if mode in {"tcp", "both"}:
            result.append(Target("tcp", port))
        if protocol == "naive" and mode in {"quic", "both"}:
            result.append(Target("udp", port))
        if domain and port != 443:
            result.append(Target("tls", 443, sni=domain))
        return result
    return []


def _awg_handshake_payload(state: AppState, target: Target) -> bytes:
    """Build a structurally sized, invalid AWG initiation for one profile."""
    ps = state.protocols.get("amneziawg")
    profiles = ps.config.get("profiles", {}) if ps else {}
    for profile in profiles.values():
        if not isinstance(profile, dict) or int(profile.get("port", 0) or 0) != target.port:
            continue
        obfuscation = profile.get("obfuscation", {})
        if not isinstance(obfuscation, dict):
            obfuscation = {}
        try:
            header = int(obfuscation.get("H1", 1)) & 0xFFFFFFFF
            padding = max(0, min(int(obfuscation.get("S1", 0)), 1024))
        except (TypeError, ValueError):
            header, padding = 1, 0
        return struct.pack("<I", header) + bytes(144 + padding)
    return struct.pack("<I", 1) + bytes(144)


def _probe(target: Target, timeout: float = 0.8,
           extra_payloads: tuple[bytes, ...] = ()) -> list[dict]:
    results = []
    for payload in (*_PAYLOADS, *extra_payloads):
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


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _invalid_client_config(state: AppState, protocol: str, listen_port: int) -> tuple[dict | None, str]:
    """Build an ephemeral client config without exposing or changing credentials."""
    if protocol not in SINGBOX_CLIENT_PROTOCOLS:
        return None, "native_client_unavailable"
    user = next((candidate for candidate in state.users if not candidate.blocked), None)
    if user is None:
        return None, "no_unblocked_user"
    from hydra.plugins.registry import get

    plugin = get(protocol)
    if plugin is None:
        return None, "plugin_unavailable"
    try:
        config = json.loads(plugin.generate_client_config(user, state))
    except (TypeError, ValueError) as exc:
        return None, f"invalid_generated_config: {exc}"
    except Exception as exc:
        return None, f"client_generation_failed: {exc.__class__.__name__}"
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list):
        return None, "client_config_unavailable"

    changed = False
    for outbound in config["outbounds"]:
        if not isinstance(outbound, dict) or outbound.get("type") != protocol:
            continue
        outbound["server"] = "127.0.0.1"
        for field in ("password", "username", "psk"):
            if field in outbound:
                outbound[field] = f"HYDRA-INVALID-{field.upper()}"
                changed = True
        tls = outbound.get("tls")
        if isinstance(tls, dict):
            tls["insecure"] = True
    # ShadowTLS carries the transport credential on its own outbound while
    # the final outbound is Trojan. Both are intentionally invalidated.
    if protocol == "shadowtls":
        for outbound in config["outbounds"]:
            if not isinstance(outbound, dict) or outbound.get("type") not in {"shadowtls", "trojan"}:
                continue
            outbound["server"] = "127.0.0.1"
            if "password" in outbound:
                outbound["password"] = "HYDRA-INVALID-PASSWORD"
                changed = True
            tls = outbound.get("tls")
            if isinstance(tls, dict):
                tls["insecure"] = True
    if not changed:
        return None, "credential_field_unavailable"
    config["inbounds"] = [{
        "type": "mixed", "tag": "hydra-selftest-in",
        "listen": "127.0.0.1", "listen_port": listen_port,
    }]
    config.setdefault("log", {})["level"] = "debug"
    return config, "ready"


def _socks_trigger(port: int) -> str:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5) as stream:
            stream.sendall(b"\x05\x01\x00")
            if stream.recv(2) != b"\x05\x00":
                return "SOCKS negotiation rejected"
            stream.sendall(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
            stream.settimeout(2.0)
            stream.recv(32)
        return ""
    except (OSError, TimeoutError) as exc:
        # Authentication failures normally surface to the local SOCKS client.
        return f"{exc.__class__.__name__}: {exc}"


def _client_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] = "true"
    environment["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] = "true"
    return environment


def _native_client_probe(state: AppState, protocol: str) -> dict:
    executable = HOST.which("sing-box")
    if not executable:
        return {"status": "missing_sing_box", "started": False}
    listen_port = _free_tcp_port()
    config, status = _invalid_client_config(state, protocol, listen_port)
    if config is None:
        return {"status": status, "started": False}
    with tempfile.TemporaryDirectory(prefix=f"hydra-{protocol}-client-") as temp_name:
        path = Path(temp_name) / "client.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        client_env = _client_environment()
        check = HOST.run(
            [executable, "check", "-c", str(path)], capture_output=True,
            text=True, timeout=10, env=client_env,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or "config check failed").strip()[-1000:]
            return {"status": "config_rejected", "started": False, "client_log": detail}
        process = HOST.popen(
            [executable, "run", "-c", str(path)], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, env=client_env,
        )
        trigger_error = "client listener did not start"
        triggered = False
        output = ""
        try:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and process.poll() is None:
                trigger_error = _socks_trigger(listen_port)
                if not trigger_error.startswith("ConnectionRefusedError"):
                    triggered = True
                    break
                time.sleep(0.05)
            time.sleep(0.5)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output, _ = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=2)
        return {
            "status": "executed" if triggered else "client_failed",
            "started": True,
            "triggered": triggered,
            "returncode": process.returncode,
            "trigger_error": trigger_error,
            "client_log": str(output or "")[-2000:],
        }


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
                normalized = dict(record)
                normalized["MESSAGE"] = decode_log_message(record.get("MESSAGE", ""))
                if _relevant_journal_record(protocol, normalized):
                    records.append(normalized)
    return records


def _relevant_journal_record(protocol: str, record: dict) -> bool:
    text = str(record.get("MESSAGE", ""))
    lowered = text.lower()
    if "hydra-antidpi-selftest" in lowered or "__hydra_antidpi_selftest__" in lowered:
        return True
    local_peer = "127.0.0.1" in lowered or "[::1]" in lowered or " ::1" in lowered
    if not local_peer:
        return False
    unit = str(record.get("_SYSTEMD_UNIT", "")).lower()
    if protocol == "amneziawg":
        return any(token in lowered for token in ("amnezia", "wireguard", "awg", "handshake", "invalid mac"))
    if unit.startswith("sing-box"):
        return protocol in lowered
    return any(owner in unit for owner in JOURNAL_UNITS[protocol])


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
                lines = [
                    line for line in handle.read().splitlines()
                    if "HYDRA-ANTIDPI-SELFTEST" in line.upper() or "__hydra_antidpi_selftest__" in line.lower()
                ]
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


def run_selftest(state: AppState, output: str | None = None, wait_seconds: float = 2.0,
                 *, full: bool = False) -> dict:
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
        "schema": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "safe_local_test": True,
        "mode": "full" if full else "malformed",
        "warning": (
            "Loopback probes test native logging and filters; they intentionally do not test "
            "external source attribution, firewall bans, or Telegram delivery."
        ),
        "environment": _environment(),
        "protocols": {},
    }
    raw: dict[str, dict[str, object]] = {}
    for protocol in SUPPORTED_PROTOCOLS:
        ps = state.protocols.get(protocol)
        enabled = bool(ps and ps.enabled)
        item: dict[str, object] = {
            "enabled": enabled, "targets": [], "probes": [], "logs": {},
            "coverage": {
                "malformed_probe_sent": False,
                "native_client_probe_sent": False,
                "native_log_observed": False,
                "filter_match": False,
                "external_source_attribution": False,
                "firewall_enforcement": False,
                "telegram_delivery": False,
            },
        }
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
            extra = (_awg_handshake_payload(state, target),) if protocol == "amneziawg" else ()
            item["probes"].extend(_probe(target, extra_payloads=extra))
        item["coverage"]["malformed_probe_sent"] = bool(item["probes"])
        if full:
            try:
                native_client = _native_client_probe(state, protocol)
            except Exception as exc:
                native_client = {
                    "status": "client_error", "started": False, "triggered": False,
                    "error_type": exc.__class__.__name__,
                }
            if native_client.get("client_log"):
                native_client["client_log"] = redact(str(native_client["client_log"]))
            item["native_client"] = native_client
            item["coverage"]["native_client_probe_sent"] = bool(native_client.get("triggered"))
        time.sleep(max(0.0, min(float(wait_seconds), 10.0)))
        until = time.time() + 0.05
        records = _journal(protocol, since, until)
        logs = _new_log_lines(before)
        item.update(_record_summary(protocol, records))
        item["logs"] = {path: len(lines) for path, lines in logs.items()}
        item["coverage"]["native_log_observed"] = bool(records or logs)
        item["coverage"]["filter_match"] = bool(
            item.get("current_filter_matches") or item.get("protocol_context_matches")
        )
        if item["coverage"]["filter_match"]:
            item["status"] = "filter_match"
        elif records or logs:
            item["status"] = "native_log_unmatched"
        else:
            item["status"] = "no_native_log_output"
        raw[protocol] = {"journal": records, "logs": logs}

    enabled_items = [item for item in report["protocols"].values() if item.get("enabled")]
    report["coverage"] = {
        "enabled_protocols": len(enabled_items),
        "native_logs": sum(bool(item["coverage"]["native_log_observed"]) for item in enabled_items),
        "filter_matches": sum(bool(item["coverage"]["filter_match"]) for item in enabled_items),
        "native_clients_executed": sum(
            bool(item["coverage"]["native_client_probe_sent"]) for item in enabled_items
        ),
        "external_test_required": [
            "source attribution from a non-whitelisted public IP",
            "ipset/firewall enforcement from that same IP",
            "Telegram delivery for an actual ALERT or BAN event",
        ],
    }

    with tempfile.TemporaryDirectory(prefix="hydra-antidpi-selftest-") as temp_name:
        root = Path(temp_name) / "hydra-antidpi-selftest"
        (root / "journal").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "report.json").write_text(redact(json.dumps(report, ensure_ascii=False, indent=2)), encoding="utf-8")
        (root / "README.txt").write_text(
            "HYDRA AntiDPI native self-test\n"
            f"Mode: {'malformed packets plus temporary invalid native clients' if full else 'malformed packets'}.\n"
            "No credentials, persistent configs, firewall rules, or services were changed.\n"
            "Local probes cannot validate external source IP attribution, firewall enforcement, or Telegram delivery.\n"
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
    captured = sum(
        1 for item in report["protocols"].values()
        if item.get("status") in {"filter_match", "native_log_unmatched"}
    )
    return {"ok": True, "archive": str(archive), "captured_protocols": captured, "report": report}
