"""Strict validation for plugin-provided HydraBox runtime material."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_DEVICE_ID = re.compile(r"^[0-9a-f]{64}$")
_DEVICE_GRANT = re.compile(r"^hwdtt1_[A-Za-z0-9_-]{43}$")
_VK_HASH = re.compile(r"^[A-Za-z0-9._~:-]{1,256}$")
_WDTT_FIELDS = frozenset({
    "type", "tag", "server", "server_port", "credential_ref", "vk_hashes",
    "workers", "obfs", "vk_auth", "vk_anon_path",
})
_WDTT_CREDENTIAL_FIELDS = frozenset({
    "kind", "credential_ref", "device_id", "device_grant",
})


def _identifier(value: object, field: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= maximum
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ValueError(f"invalid HydraBox {field}")
    return value


def validate_wdtt_endpoint(item: dict[str, Any]) -> dict[str, Any]:
    """Validate the bounded WDTT policy-v2 native endpoint."""
    unknown = set(item) - _WDTT_FIELDS
    if unknown:
        raise ValueError(
            f"unsupported WDTT endpoint field: {sorted(unknown)[0]}",
        )
    server = item.get("server")
    if (
        not isinstance(server, str)
        or not 0 < len(server) <= 253
        or server != server.strip()
        or any(character.isspace() or ord(character) < 32 for character in server)
        or any(character in server for character in "/?#@")
    ):
        raise ValueError("invalid WDTT server")
    port = item.get("server_port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid WDTT server_port")
    _identifier(item.get("credential_ref"), "credential_ref")
    hashes = item.get("vk_hashes")
    if (
        not isinstance(hashes, list)
        or not 1 <= len(hashes) <= 4
        or any(not isinstance(value, str) or not _VK_HASH.fullmatch(value) for value in hashes)
        or len(hashes) != len(set(hashes))
    ):
        raise ValueError("WDTT vk_hashes must contain 1..4 unique call hashes")
    workers = item.get("workers", 18)
    if type(workers) is not int or workers not in {9, 18, 27, 36}:
        raise ValueError("WDTT workers must be 9, 18, 27, or 36")
    if item.get("obfs", "audio") not in {"audio", "video"}:
        raise ValueError("invalid WDTT obfs mode")
    if item.get("vk_auth", "auto") not in {"auto", "anonymous", "account"}:
        raise ValueError("invalid WDTT VK authentication mode")
    if item.get("vk_anon_path", "vkcalls") != "vkcalls":
        raise ValueError("invalid WDTT anonymous authentication path")
    return item


def parse_hydrabox_material(
    material: object,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Return one bounded runtime projection and its encrypted credentials."""
    if not isinstance(material, Mapping) or set(material) != {
        "projection", "credentials",
    }:
        raise ValueError("invalid HydraBox plugin material")
    projection = material.get("projection")
    credentials = material.get("credentials")
    if not isinstance(projection, dict) or not isinstance(credentials, list):
        raise ValueError("invalid HydraBox plugin material")
    try:
        detached_projection = json.loads(json.dumps(projection, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("HydraBox plugin projection must be JSON") from exc
    detached_credentials = [
        _validate_wdtt_credential(value)
        for value in credentials
    ]
    return detached_projection, detached_credentials


def _validate_wdtt_credential(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _WDTT_CREDENTIAL_FIELDS:
        raise ValueError("invalid HydraBox WDTT credential material")
    if value.get("kind") != "wdtt_device_grant":
        raise ValueError("invalid HydraBox WDTT credential kind")
    credential_ref = _identifier(value.get("credential_ref"), "credential_ref")
    device_id = value.get("device_id")
    device_grant = value.get("device_grant")
    if not isinstance(device_id, str) or not _DEVICE_ID.fullmatch(device_id):
        raise ValueError("invalid HydraBox WDTT device_id")
    if not isinstance(device_grant, str) or not _DEVICE_GRANT.fullmatch(device_grant):
        raise ValueError("invalid HydraBox WDTT device_grant")
    return {
        "kind": "wdtt_device_grant",
        "credential_ref": credential_ref,
        "device_id": device_id,
        "device_grant": device_grant,
    }


def validate_material_binding(
    credentials: list[dict[str, str]],
    objects: list[tuple[str, dict[str, Any]]],
) -> None:
    """Require one encrypted grant for every WDTT endpoint and nothing else."""
    endpoint_refs = {
        item["credential_ref"]
        for section, item in objects
        if section == "endpoints" and item.get("type") == "wdtt"
    }
    credential_refs = [item["credential_ref"] for item in credentials]
    if len(credential_refs) != len(set(credential_refs)):
        raise ValueError("duplicate HydraBox credential_ref")
    if endpoint_refs != set(credential_refs):
        raise ValueError("WDTT endpoint and encrypted credential bindings differ")


__all__ = [
    "parse_hydrabox_material",
    "validate_material_binding",
    "validate_wdtt_endpoint",
]
