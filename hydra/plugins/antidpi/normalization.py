"""Structured log normalization for AntiScan decoy evidence.

Only an explicit scanner path requested from a decoy surface is evidence here.
Generic TLS failures, HTTP status codes, authentication heuristics and
method-only classification are not parsed: they describe ordinary Internet
noise or legitimate clients, not a proven probe.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from hydra.core.yandex_cdn import contains_peer
from hydra.plugins.antidpi.adapters import remote_ip

Normalizer = Callable[[dict], "tuple[str, dict] | None"]

# Scanner path prefixes checked against the normalized request path only.
DECOY_PATH_TOKENS = (
    "/.env",
    "/.git/",
    "/wp-login",
    "/xmlrpc.php",
    "/actuator",
    "/cgi-bin/",
    "/server-status",
)

# Bound the stored path so an attacker cannot inflate plugin state.
MAX_EVIDENCE_PATH = 120


def _bounded_path(path: str) -> str:
    cleaned = "".join(character for character in path if character.isprintable())
    return cleaned[:MAX_EVIDENCE_PATH]


def _request_path(request: dict) -> str:
    return str(request.get("uri", request.get("path", ""))).split("?", 1)[0]


def _decoy_path_is_suspicious(path: str) -> bool:
    """Match scanner paths against the normalized path, never the query.

    ``/?next=/.env`` is a regular link with a scanner-looking parameter, not
    a probe of the credential file itself.
    """
    if not path:
        return False
    if any(path.startswith(token) for token in DECOY_PATH_TOKENS):
        return True
    # Credential files are probed at any depth: /.env, /backup/.env.bak.
    return any(part == ".env" or part.startswith(".env.") for part in path.split("/"))


def normalize_decoy_record(record: dict) -> tuple[str, dict] | None:
    """Recognize an explicit scanner path on a decoy surface."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    address = remote_ip(
        request.get("remote_ip", request.get("remote_addr", "")),
    )
    if address is None:
        return None
    path = _request_path(request).lower()
    if not _decoy_path_is_suspicious(path):
        return None
    return address, {
        "kind": "decoy_scan",
        "protocol": "https",
        "reason": "scanner_path",
        "source": "caddy-decoy",
        "attribution": "direct",
        "path": _bounded_path(path),
    }


def normalize_vless_cdn_record(
    record: dict,
    *,
    is_cdn_peer: Callable[[object], bool] = contains_peer,
) -> tuple[str, dict] | None:
    """Suppress a scanner record only for a verified VLESS-CDN socket peer."""
    event = normalize_decoy_record(record)
    return None if event is None or is_cdn_peer(event[0]) else event
