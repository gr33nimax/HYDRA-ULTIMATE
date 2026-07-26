"""Collection, redaction, and archive helpers for AntiDPI self-tests."""
from __future__ import annotations

import json
import platform
import re
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.adapters import decode_log_message, parse_protocol_line
from hydra.plugins.antidpi.normalization import normalize_naive_decoy_record


def environment(
    host,
    *,
    version: str,
    journal_units: dict[str, tuple[str, ...]],
) -> dict:
    units = sorted(
        {
            "hydra-antidpi",
            "hydra-awg-antidpi-debug",
            "caddy-l4",
            *[
                unit
                for units in journal_units.values()
                for unit in units
            ],
        },
    )
    services = {}
    for unit in units:
        result = host.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
        )
        services[unit] = result.stdout.strip() or "unknown"
    binaries = {}
    for name in ("sing-box", "awg", "caddy-l4", "caddy-naive"):
        executable = host.which(name)
        if not executable:
            continue
        result = host.run(
            [executable, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or result.stderr or "").strip().splitlines()
        binaries[name] = (
            " | ".join(output[:3])[:500]
            if output
            else "unknown"
        )
    return {
        "hydra_version": version,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "services": services,
        "binaries": binaries,
    }


def relevant_journal_record(
    protocol: str,
    record: dict,
    *,
    journal_units: dict[str, tuple[str, ...]],
) -> bool:
    text = str(record.get("MESSAGE", ""))
    lowered = text.lower()
    if (
        "hydra-antidpi-selftest" in lowered
        or "__hydra_antidpi_selftest__" in lowered
    ):
        return True
    local_peer = (
        "127.0.0.1" in lowered
        or "[::1]" in lowered
        or " ::1" in lowered
    )
    if not local_peer:
        return False
    unit = str(record.get("_SYSTEMD_UNIT", "")).lower()
    if protocol == "amneziawg":
        return any(
            token in lowered
            for token in (
                "amnezia",
                "wireguard",
                "awg",
                "handshake",
                "invalid mac",
            )
        )
    if unit.startswith("sing-box"):
        return protocol in lowered
    return any(owner in unit for owner in journal_units[protocol])


def journal(
    protocol: str,
    since: float,
    until: float,
    *,
    host,
    journal_units: dict[str, tuple[str, ...]],
) -> list[dict]:
    base = [
        "journalctl",
        "--no-pager",
        "-o",
        "json",
        f"--since=@{since:.3f}",
        f"--until=@{until:.3f}",
    ]
    command = list(base)
    for unit in journal_units[protocol]:
        command.extend(("-u", unit))
    commands = [command]
    if protocol == "amneziawg":
        commands.append([*base, "-k"])
    records = []
    for journal_command in commands:
        result = host.run(
            journal_command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            normalized = dict(record)
            normalized["MESSAGE"] = decode_log_message(
                record.get("MESSAGE", ""),
            )
            if relevant_journal_record(
                protocol,
                normalized,
                journal_units=journal_units,
            ):
                records.append(normalized)
    return records


def offsets(paths: tuple[Path, ...]) -> dict[Path, int]:
    result = {}
    for path in paths:
        try:
            result[path] = path.stat().st_size
        except OSError:
            result[path] = 0
    return result


def new_log_lines(before: dict[Path, int]) -> dict[str, list[str]]:
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
                lines = [
                    line
                    for line in handle.read().splitlines()
                    if (
                        "HYDRA-ANTIDPI-SELFTEST" in line.upper()
                        or "__hydra_antidpi_selftest__" in line.lower()
                    )
                ]
        except OSError:
            lines = []
        if lines:
            result[str(path)] = lines
    return result


def secret_values(state: AppState) -> set[str]:
    secrets: set[str] = set()
    sensitive = re.compile(
        r"pass|token|secret|private|psk|uuid|key",
        re.IGNORECASE,
    )

    def visit(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key))
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child, key)
        elif (
            sensitive.search(key)
            and isinstance(value, str)
            and len(value) >= 6
        ):
            secrets.add(value)

    visit(asdict(state))
    return secrets


def redactor(state: AppState) -> Callable[[str], str]:
    secrets = sorted(secret_values(state), key=len, reverse=True)
    substitutions = (
        (
            re.compile(r"(?i)(authorization\s*[:=]\s*)(\S+)"),
            r"\1[REDACTED]",
        ),
        (
            re.compile(
                r"(?i)((?:password|passwd|token|secret|private_key|psk)"
                r"\s*[:=]\s*)[^\s,}\]]+",
            ),
            r"\1[REDACTED]",
        ),
        (
            re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"),
            r"\1[REDACTED]@",
        ),
    )

    def redact(text: str) -> str:
        result = str(text)
        for secret in secrets:
            result = result.replace(secret, "[REDACTED]")
        for pattern, replacement in substitutions:
            result = pattern.sub(replacement, result)
        return result

    return redact


def record_summary(protocol: str, records: list[dict]) -> dict:
    pairs = [
        (record, str(record.get("MESSAGE", "")))
        for record in records
        if record.get("MESSAGE")
    ]
    native_matches = []
    contextual_matches = []
    for record, message in pairs:
        unit = str(record.get("_SYSTEMD_UNIT", ""))
        if match := parse_protocol_line(unit, message):
            native_matches.append(
                {"unit": unit, "ip": match[0], "event": match[1]},
            )
        if match := parse_protocol_line(protocol, message):
            contextual_matches.append(
                {"unit": unit, "ip": match[0], "event": match[1]},
            )
    return {
        "journal_records": len(records),
        "journal_messages": len(pairs),
        "current_filter_matches": native_matches,
        "protocol_context_matches": contextual_matches,
    }


def log_filter_matches(
    protocol: str,
    logs: dict[str, list[str]],
) -> list[dict]:
    matches = []
    if protocol != "naive":
        return matches
    for path, lines in logs.items():
        for line in lines:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if match := normalize_naive_decoy_record(record):
                matches.append(
                    {"unit": path, "ip": match[0], "event": match[1]},
                )
    return matches


def write_selftest_archive(
    archive: Path,
    *,
    report: dict,
    raw: dict[str, dict[str, object]],
    redact: Callable[[str], str],
    full: bool,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="hydra-antidpi-selftest-",
    ) as temp_name:
        root = Path(temp_name) / "hydra-antidpi-selftest"
        (root / "journal").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "report.json").write_text(
            redact(json.dumps(report, ensure_ascii=False, indent=2)),
            encoding="utf-8",
        )
        mode = (
            "malformed packets plus temporary invalid native clients"
            if full
            else "malformed packets"
        )
        (root / "README.txt").write_text(
            "HYDRA AntiDPI native self-test\n"
            f"Mode: {mode}.\n"
            "No credentials, persistent configs, firewall rules, or services "
            "were changed.\n"
            "Local probes cannot validate external source IP attribution, "
            "firewall enforcement, or Telegram delivery.\n"
            "The bundle is automatically redacted, but review it before "
            "sharing.\n",
            encoding="utf-8",
        )
        _write_raw_selftest(root, raw, redact)
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(root, arcname=root.name)
    archive.chmod(0o600)


def _write_raw_selftest(
    root: Path,
    raw: dict[str, dict[str, object]],
    redact: Callable[[str], str],
) -> None:
    for protocol, captured in raw.items():
        journal_text = "\n".join(
            json.dumps(record, ensure_ascii=False)
            for record in captured["journal"]
        )
        (root / "journal" / f"{protocol}.jsonl").write_text(
            redact(journal_text),
            encoding="utf-8",
        )
        for index, (path, lines) in enumerate(
            captured["logs"].items(),
            1,
        ):
            label = Path(path).name.replace(".", "-")
            (root / "logs" / f"{protocol}-{index}-{label}.log").write_text(
                redact("\n".join(lines)),
                encoding="utf-8",
            )
