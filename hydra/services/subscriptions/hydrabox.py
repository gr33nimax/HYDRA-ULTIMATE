"""HydraBox SubscriptionData v1 envelope generation."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.metadata import get_subscription_url


HYDRABOX_API_VERSION = "hydrabox.io/subscription/v1"
HYDRABOX_KIND = "SubscriptionData"
HYDRABOX_MEDIA_TYPE = "application/vnd.hydrabox.subscription+json"
HYDRABOX_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_MAX_SEQUENCE = 9_007_199_254_740_991
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_ALLOWED_OUTBOUND_TYPES = frozenset({
    "socks", "http", "vmess", "trojan", "naive", "shadowtls", "vless",
    "mieru", "anytls", "trusttunnel", "hysteria", "hysteria2", "tuic",
    "sudoku", "snell",
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
_QWDT_FIELDS = frozenset({
    "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
})


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric value: {value}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_loads(payload: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid plugin JSON projection") from exc
    if not isinstance(value, dict):
        raise ValueError("plugin JSON projection must be an object")
    return value


def _validate_depth(value: Any, depth: int = 1) -> None:
    if depth > 64:
        raise ValueError("HydraBox runtime exceeds the JSON depth limit")
    if isinstance(value, dict):
        for nested in value.values():
            _validate_depth(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _validate_depth(nested, depth + 1)


def _validate_remote_values(value: Any, path: tuple[str, ...] = ()) -> None:
    if value is None:
        raise ValueError(f"explicit null is forbidden at {'.'.join(path)}")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = key.lower()
            if normalized in _LOCAL_AUTHORITY_FIELDS:
                raise ValueError(f"local authority field is forbidden: {key}")
            if normalized in _QWDT_FIELDS:
                raise ValueError(f"qWDTT field is forbidden: {key}")
            _validate_remote_values(nested, (*path, key))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _validate_remote_values(nested, (*path, str(index)))


def _validate_tag(tag: object) -> str:
    if not isinstance(tag, str) or not tag or len(tag) > 512:
        raise ValueError("native tag must contain 1..512 characters")
    if tag != tag.strip() or any(ord(character) < 32 for character in tag):
        raise ValueError(f"invalid native tag: {tag!r}")
    if tag.startswith("__hydrabox.") or tag in _RESERVED_TAGS:
        raise ValueError(f"reserved HydraBox tag: {tag}")
    return tag


def _runtime_objects(
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
            _validate_remote_values(item, (section,))
            if section == "endpoints":
                if item.get("system", False) is not False:
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


def _entrypoints(
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


def _profile_id(plugin_name: str, section: str, tag: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9._:-]+", "-", plugin_name).strip("-._:")
    prefix = prefix or "profile"
    digest = hashlib.sha256(f"{section}\0{tag}".encode()).hexdigest()[:16]
    return f"{prefix[:110]}-{digest}"


def _parse_timestamp(value: str, field: str) -> datetime:
    source = value.strip()
    if "T" not in source:
        suffix = "T23:59:59Z" if field == "expires_at" else "T00:00:00Z"
        source = f"{source}{suffix}"
    if source.endswith("Z"):
        source = source[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(source)
    except ValueError as exc:
        raise ValueError(f"invalid RFC 3339 {field}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp(value: str, field: str) -> str:
    return _parse_timestamp(value, field).isoformat().replace("+00:00", "Z")


def _issuer(user: User, state: AppState) -> str:
    parsed = urlsplit(get_subscription_url(user, state))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("HydraBox issuer must be an HTTPS origin")
    return f"https://{parsed.netloc}"


def _validate_envelope_identity(user: User, state: AppState) -> None:
    if not _ID_PATTERN.fullmatch(user.uuid) or len(user.uuid) > 128:
        raise ValueError("invalid HydraBox subscription_id")
    if type(state.revision) is not int or not 0 <= state.revision <= _MAX_SEQUENCE:
        raise ValueError("invalid HydraBox sequence")


def generate_hydrabox_subscription(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> dict[str, Any]:
    """Build an activatable plaintext HydraBox SubscriptionData v1 document."""
    _validate_envelope_identity(user, state)
    document: dict[str, list[dict[str, Any]]] = {
        "outbounds": [],
        "endpoints": [],
    }
    profiles: list[dict[str, Any]] = []
    native_tags: set[str] = set()
    profile_ids: set[str] = set()

    for plugin in plugins.enabled_transports(state):
        if not plugin.meta.capabilities.subscription_enabled:
            continue
        try:
            payload = plugins.singbox_client_config(plugin, user, state)
        except Exception as exc:
            raise ValueError(
                f"failed to generate {plugin.meta.name} HydraBox projection",
            ) from exc
        if not payload:
            continue
        projection = _strict_loads(payload)
        _validate_depth(projection)
        objects = _runtime_objects(projection)
        entrypoints = _entrypoints(projection, objects)
        label = plugin.meta.display_name or plugin.meta.description or plugin.meta.name
        multiple = len(entrypoints) > 1
        for section, item in objects:
            tag = item["tag"]
            if tag in native_tags:
                raise ValueError(f"duplicate native tag: {tag}")
            native_tags.add(tag)
            document[section].append(item)
        for section, tag in entrypoints:
            profile_id = _profile_id(plugin.meta.name, section, tag)
            if profile_id in profile_ids:
                raise ValueError(f"duplicate HydraBox profile id: {profile_id}")
            profile_ids.add(profile_id)
            profiles.append({
                "id": profile_id,
                "name": f"{label} — {tag}" if multiple else label,
                "entrypoint": {"section": section, "tag": tag},
                "enabled": True,
            })

    if not profiles:
        raise ValueError("HydraBox subscription requires an enabled profile")
    if len(profiles) > 4096:
        raise ValueError("HydraBox subscription exceeds the profile limit")
    runtime_document = {
        section: values for section, values in document.items() if values
    }
    issued_at = _timestamp(
        user.created_at or "1970-01-01T00:00:00Z",
        "issued_at",
    )
    envelope: dict[str, Any] = {
        "api_version": HYDRABOX_API_VERSION,
        "kind": HYDRABOX_KIND,
        "issuer": _issuer(user, state),
        "subscription_id": user.uuid,
        "channel": "stable",
        "sequence": state.revision,
        "issued_at": issued_at,
        "default_profile_id": profiles[0]["id"],
        "metadata": {"name": {"default": f"HYDRA — {user.email}"}},
        "runtime": {"format": "sing-box-json", "document": runtime_document},
        "profiles": profiles,
    }
    if user.expiry_date:
        expires_at = _timestamp(user.expiry_date, "expires_at")
        if _parse_timestamp(expires_at, "expires_at") <= _parse_timestamp(
            issued_at,
            "issued_at",
        ):
            raise ValueError("HydraBox expires_at must be later than issued_at")
        envelope["expires_at"] = expires_at
    _validate_remote_values(envelope)
    return envelope


def serialize_hydrabox_subscription(subscription: dict[str, Any]) -> str:
    """Serialize one envelope as bounded strict UTF-8 JSON."""
    content = json.dumps(
        subscription,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    if len(content.encode("utf-8")) > HYDRABOX_MAX_RESPONSE_BYTES:
        raise ValueError("HydraBox subscription exceeds 16 MiB")
    return content
