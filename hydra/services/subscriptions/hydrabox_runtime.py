"""Validation and projection helpers for HydraBox sing-box runtime objects."""
from __future__ import annotations

from typing import Any


_ALLOWED_OUTBOUND_TYPES = frozenset({
    "socks", "http", "vmess", "trojan", "naive", "shadowtls", "vless",
    "mieru", "anytls", "trusttunnel", "hysteria", "hysteria2", "tuic",
    "sudoku", "snell", "call",
})
_RESERVED_TAGS = frozenset({
    "select", "direct", "lowest", "lowest-open", "lowest-free", "mixed",
})
_REFERENCE_FIELDS = frozenset({"detour", "outbound", "endpoint"})
_LOCAL_AUTHORITY_FIELDS = frozenset({
    "certificate_path", "client_certificate_path", "client_key_path",
    "command", "commands", "config_path", "database_path", "exec",
    "executable", "interface", "interface_name", "key_path", "listen",
    "listen_port", "network_interface", "plugin", "plugin_opts", "process",
    "private_key_path", "socket_path", "state_dir", "state_directory",
    "working_directory",
})


def validate_depth(value: Any, depth: int = 1) -> None:
    if depth > 64:
        raise ValueError("HydraBox runtime exceeds the JSON depth limit")
    if isinstance(value, dict):
        for nested in value.values():
            validate_depth(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            validate_depth(nested, depth + 1)


def validate_remote_values(value: Any, path: tuple[str, ...] = ()) -> None:
    if value is None:
        raise ValueError(f"explicit null is forbidden at {'.'.join(path)}")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = key.lower()
            if normalized in _LOCAL_AUTHORITY_FIELDS:
                raise ValueError(f"local authority field is forbidden: {key}")
            validate_remote_values(nested, (*path, key))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            validate_remote_values(nested, (*path, str(index)))


def _validate_tag(tag: object) -> str:
    if not isinstance(tag, str) or not tag or len(tag) > 512:
        raise ValueError("native tag must contain 1..512 characters")
    if tag != tag.strip() or any(ord(character) < 32 for character in tag):
        raise ValueError(f"invalid native tag: {tag!r}")
    if tag.startswith("__hydra.") or tag in _RESERVED_TAGS:
        raise ValueError(f"reserved Hydra tag: {tag}")
    return tag


def runtime_objects(
    projection: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    for section in ("outbounds", "endpoints"):
        values = projection.get(section, [])
        if not isinstance(values, list):
            raise ValueError(f"runtime {section} must be an array")
        for raw in values:
            if not isinstance(raw, dict):
                raise ValueError(f"runtime {section} item must be an object")
            object_type = raw.get("type")
            allowed = (
                object_type in _ALLOWED_OUTBOUND_TYPES
                if section == "outbounds"
                else object_type == "wireguard"
            )
            if not allowed:
                continue
            item = dict(raw)
            _validate_tag(item.get("tag"))
            validate_remote_values(item, (section,))
            if section == "endpoints":
                system = item.get("system", False)
                if not isinstance(system, bool) or system:
                    raise ValueError("system WireGuard is forbidden")
                item["system"] = False
            result.append((section, item))
    return result


def _references(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in _REFERENCE_FIELDS:
                if nested:
                    if not isinstance(nested, str):
                        raise ValueError(f"runtime reference {key} must be a tag")
                    result.add(nested)
            elif key == "outbounds":
                if not isinstance(nested, list) or any(
                    not isinstance(item, str) for item in nested
                ):
                    raise ValueError("runtime outbounds reference must be tag array")
                result.update(nested)
            else:
                result.update(_references(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_references(nested))
    return result


def entrypoints(
    projection: dict[str, Any],
    objects: list[tuple[str, dict[str, Any]]],
) -> list[tuple[str, str]]:
    by_tag = {item["tag"]: item for _, item in objects}
    if len(by_tag) != len(objects):
        raise ValueError("duplicate native tag in plugin projection")
    references = {tag: _references(item) for tag, item in by_tag.items()}
    for tag, targets in references.items():
        missing = targets - set(by_tag)
        if missing:
            raise ValueError(
                f"runtime object {tag} references missing tag {sorted(missing)[0]}",
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(tag: str) -> None:
        if tag in visiting:
            raise ValueError(f"cyclic runtime reference at tag {tag}")
        if tag in visited:
            return
        visiting.add(tag)
        for target in references[tag]:
            visit(target)
        visiting.remove(tag)
        visited.add(tag)

    for tag in by_tag:
        visit(tag)

    referenced = {target for targets in references.values() for target in targets}
    roots = [
        (section, item["tag"])
        for section, item in objects
        if item["tag"] not in referenced
    ]
    route = projection.get("route", {})
    preferred = route.get("final") if isinstance(route, dict) else None
    return sorted(roots, key=lambda entry: entry[1] != preferred)


def requested_permissions(objects: list[tuple[str, dict[str, Any]]]) -> list[str]:
    sections = {section for section, _ in objects}
    return [permission for section, permission in (
        ("outbounds", "network.outbound"),
        ("endpoints", "network.endpoint.wireguard"),
    ) if section in sections]


__all__ = [
    "entrypoints",
    "requested_permissions",
    "runtime_objects",
    "validate_depth",
    "validate_remote_values",
]
