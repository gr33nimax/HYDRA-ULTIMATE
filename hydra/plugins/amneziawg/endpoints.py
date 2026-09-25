"""Server endpoint projection: desired state onto the core's ``wireguard`` endpoint.

The core serves AmneziaWG itself now, so the server side is a configuration object instead of an
interface file. This module owns that projection and the refusal rules around it: a generation the
stored material cannot fill, or padding below the header-protection nonce, fails here rather than in
a half-applied runtime configuration.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Mapping
from typing import Any

from .presets import validate_params

# Stored material keeps the interface vocabulary (the names a config file and the directive parser
# use); only this projection speaks the core's snake_case.
GENERATION_FIELDS_30: tuple[tuple[str, str], ...] = (
    ("HeaderProtectionKey", "header_protection_key"),
    ("ContentPaddingAddition", "content_padding_addition"),
    ("RekeyAfterTime", "rekey_after_time"),
    ("RekeyTimeout", "rekey_timeout"),
    ("RejectAfterTime", "reject_after_time"),
    ("KeepaliveTimeout", "keepalive_timeout"),
)
GENERATION_FIELD_MAX_HANDSHAKE: tuple[str, str] = (
    "MaxHandshakeAttempts",
    "max_handshake_attempts",
)
GENERATION_FIELDS_31: tuple[tuple[str, str], ...] = (
    ("RandomTrailers", "random_trailers"),
    ("DisableCookies", "disable_cookies"),
)

_NUMERIC_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4")
_HEADER_KEYS = ("H1", "H2", "H3", "H4")
_LEGACY_INJECTION_KEY = "I1"


def _number(value: Any, *, field: str) -> int:
    """Read one stored number, naming the field when the value is not a number."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"AmneziaWG {field} is not a number: {value!r}") from exc


def _header(value: Any, *, field: str) -> int | str:
    """A header is a single value or a range; the core accepts both, so keep the shape."""
    text = str(value).strip()
    return text if "-" in text else _number(text, field=field)


def _is_plain_mode(protocol_mode: object) -> bool:
    return str(protocol_mode).strip() in ("", "2.0")


# The ranges the reference implementation documents for a 3.x profile. HYDRA generates them for a host it
# serves itself; a value the operator already has is never replaced.
GENERATION_RANGES_30: tuple[tuple[str, str], ...] = (
    ("ContentPaddingAddition", "10-100"),
    ("RekeyAfterTime", "100-120"),
    ("RekeyTimeout", "3-7"),
    ("RejectAfterTime", "150-180"),
    ("KeepaliveTimeout", "5-15"),
)


def generate_generation_material(protocol_mode: str, rng: Any | None = None) -> dict[str, Any]:
    """Material HYDRA owns for a generation it serves: a fresh header-protection key and the ranges.

    The 3.1 pair is random trailers on and cookies off: that combination *is* the generation, not a
    setting to leave open — a profile carrying the other one is not serving 3.1, and every client
    that reads a link of this generation expects exactly this pair.
    """
    if _is_plain_mode(protocol_mode):
        return {}
    source = rng or secrets
    material: dict[str, Any] = {
        "HeaderProtectionKey": base64.b64encode(source.token_bytes(32)).decode(),
    }
    material.update(dict(GENERATION_RANGES_30))
    if str(protocol_mode).strip() == "3.1":
        material["RandomTrailers"] = True
        material["DisableCookies"] = True
    return material


def canonical_generation(
    generation: Mapping[str, Any] | None,
    protocol_mode: str,
) -> dict[str, Any]:
    """Return the generation material a mode actually serves.

    The 3.1 pair is not a stored preference: random trailers on and cookies off *is* the
    generation. An earlier release could persist the opposite pair next to ``protocol_mode: 3.1``,
    and reading that material back verbatim made the served endpoint and the exported links agree
    on something that is not 3.1 at all. Canonicalizing here is what keeps the endpoint, the
    ``wg://`` link and every subscription saying the same true thing, whichever version wrote the
    stored material.
    """
    material = dict(generation) if isinstance(generation, Mapping) else {}
    mode = str(protocol_mode).strip()
    if mode == "3.1":
        material["RandomTrailers"] = True
        material["DisableCookies"] = True
    elif not _is_plain_mode(mode):
        # 3.0 replaced obfuscation with header protection and nothing else, so the two 3.1 fields
        # describe a shape this generation does not have.
        material.pop("RandomTrailers", None)
        material.pop("DisableCookies", None)
    return material


def obfuscation_block(obfuscation: dict[str, Any], *, include_i1: bool) -> dict[str, Any]:
    """Project stored obfuscation onto the core's field names."""
    block: dict[str, Any] = {}
    for key in _NUMERIC_KEYS:
        value = obfuscation.get(key)
        if value not in (None, ""):
            block[key.lower()] = _number(value, field=key)
    for key in _HEADER_KEYS:
        value = obfuscation.get(key)
        if value not in (None, ""):
            block[key.lower()] = _header(value, field=key)
    if include_i1:
        value = obfuscation.get(_LEGACY_INJECTION_KEY)
        if value not in (None, ""):
            block[_LEGACY_INJECTION_KEY.lower()] = str(value)
    return block


def generation_block(generation: Mapping[str, Any], protocol_mode: str) -> dict[str, Any]:
    """Return the 3.x fields for one generation, or refuse naming what is missing."""
    if _is_plain_mode(protocol_mode):
        return {}
    generation = canonical_generation(generation, protocol_mode)
    block: dict[str, Any] = {}
    for source, target in GENERATION_FIELDS_30:
        value = generation.get(source)
        if value in (None, ""):
            raise ValueError(
                f"AmneziaWG generation material is missing {source} for mode {protocol_mode}",
            )
        block[target] = value
    optional_source, optional_target = GENERATION_FIELD_MAX_HANDSHAKE
    optional_value = generation.get(optional_source)
    if optional_value not in (None, ""):
        block[optional_target] = optional_value
    if str(protocol_mode).strip() == "3.1":
        # The pair cannot be missing here: ``canonical_generation`` supplies it for this mode.
        for source, target in GENERATION_FIELDS_31:
            block[target] = bool(generation[source])
    return block


def amnezia_block(
    obfuscation: dict[str, Any],
    generation: Mapping[str, Any] | None,
    protocol_mode: str,
) -> dict[str, Any]:
    """Build the whole ``amnezia`` object the core expects for one generation."""
    valid, reason = validate_params(obfuscation, protocol_mode=protocol_mode)
    if not valid:
        raise ValueError(reason)
    block = obfuscation_block(obfuscation, include_i1=_is_plain_mode(protocol_mode))
    block.update(generation_block(generation or {}, protocol_mode))
    return block


def build_peer(
    *,
    public_key: str,
    preshared_key: str | None,
    address: str,
) -> dict[str, Any]:
    """One peer: identity, optional pre-shared key, and the address it may use."""
    peer: dict[str, Any] = {
        "public_key": public_key,
        "allowed_ips": [address],
    }
    if preshared_key:
        peer["pre_shared_key"] = preshared_key
    return peer


def build_endpoint(
    *,
    tag: str,
    address: str,
    private_key: str,
    port: int | str,
    mtu: int | str,
    peers: list[dict[str, Any]],
    amnezia: dict[str, Any],
) -> dict[str, Any]:
    """One served endpoint: the server side of a profile's tunnel."""
    return {
        "type": "wireguard",
        "tag": tag,
        "address": [address],
        "private_key": private_key,
        "listen_port": _number(port, field="listen_port"),
        "mtu": _number(mtu, field="mtu"),
        "peers": peers,
        "amnezia": amnezia,
    }
