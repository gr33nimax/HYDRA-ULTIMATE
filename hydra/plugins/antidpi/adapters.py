"""Strict protocol-reject adapters for the AntiScan evidence allowlist.

These parsers emit evidence, not verdicts.  Only a protocol-owned
authentication/handshake rejection with an exactly attributed external peer
qualifies; generic TLS noise, HTTP status codes, packet rates and unrelated
service messages are never evidence and are not parsed at all.
"""

from __future__ import annotations

import ipaddress
import json
import re

# One anchored grammar per enabled protocol reject.  A pattern must bind the
# inbound tag, the protocol-owned error and the peer endpoint in one record;
# matching a bare keyword anywhere in a journal line is forbidden.
_PROTOCOL_REJECTS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        # Snell is a direct TCP listener, so the peer is the real client.
        # ``message authentication failed`` on the record header proves the
        # caller could not produce a valid encrypted Snell frame.
        "snell",
        "record_auth_failed",
        "direct",
        re.compile(
            r"inbound/snell\[[^\]]+\]:\s*"
            r"process connection from\s+(?P<peer>\[[0-9a-fA-F:]+\]|[0-9.]+):(?P<port>\d+):\s*"
            r"snell:\s*serve\s+(?P<served>\[[0-9a-fA-F:]+\]|[0-9.]+):(?P<served_port>\d+):\s*"
            r"read request:\s*open record header:\s*cipher:\s*"
            r"message authentication failed",
        ),
    ),
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def decode_log_message(value: object) -> str:
    """Decode journald's JSON byte-array representation used by sing-box.

    Some sing-box-extended builds write ``[]byte`` to stdout. systemd stores
    that as an array in JSON output instead of a normal MESSAGE string.
    """
    candidate = value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]") and len(stripped) <= 1_000_000:
            try:
                candidate = json.loads(stripped)
            except (TypeError, ValueError):
                candidate = value
    if (
        isinstance(candidate, list)
        and len(candidate) <= 262_144
        and all(isinstance(item, int) and 0 <= item <= 255 for item in candidate)
    ):
        text = bytes(candidate).decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    return _ANSI_ESCAPE.sub("", text)


def remote_ip(value: object) -> str | None:
    """Return the canonical IP from a raw address or host:port endpoint."""
    raw = str(value or "").strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1 : raw.index("]")]
    else:
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError:
            raw = raw.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        return None


# Compatibility name for older parser tests and internal imports.
_remote_ip = remote_ip


def parse_protocol_line(service: str, line: object) -> tuple[str, dict] | None:
    """Return one proven protocol reject, or ``None`` for anything weaker."""
    _ = service  # kept for call-site compatibility; the grammar owns the match
    text = decode_log_message(line)
    for protocol, reason, attribution, pattern in _PROTOCOL_REJECTS:
        match = pattern.search(text)
        if match is None:
            continue
        peer = remote_ip(match.group("peer"))
        served = remote_ip(match.group("served"))
        if peer is None or served is None or peer != served:
            # The wrapper and the protocol-owned error must agree on the peer;
            # a mismatch means the record cannot be attributed.
            continue
        return peer, {
            "kind": "protocol_reject",
            "protocol": protocol,
            "reason": reason,
            "source": "journal",
            "attribution": attribution,
        }
    return None
