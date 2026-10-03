"""Hydra Subscription v2 generation for the HydraBox delivery format."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from hydra.core.configuration_names import resolve_configuration_name
from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.metadata import get_subscription_url
from hydra.services.subscriptions.hydrabox_runtime import (
    entrypoints as _entrypoints,
    requested_permissions as _requested_permissions,
    runtime_objects as _runtime_objects,
    validate_depth as _validate_depth,
    validate_remote_values as _validate_remote_values,
)
from hydra.services.subscriptions.node_exports import (
    ManagedNodeProfileReader,
    NodeSubscriptionProfile,
    node_profiles_for_user,
)
from hydra.services.subscriptions.profile_names import (
    hydrabox_profile_id,
    hydrabox_profile_name,
    hydrabox_resource_id,
)


HYDRABOX_API_VERSION = "hydra.io/subscription/v2"
HYDRABOX_KIND = "Subscription"
HYDRABOX_MEDIA_TYPE = "application/vnd.hydra.subscription+json"
HYDRABOX_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_MAX_SEQUENCE = 9_007_199_254_740_991
_PAYLOAD_REVISION_BITS = 16
# Increment whenever renderer code can change JSON for unchanged persisted state.
_HYDRABOX_PAYLOAD_REVISION = 4
_MAX_STATE_REVISION = _MAX_SEQUENCE >> _PAYLOAD_REVISION_BITS
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
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


def _validate_envelope_identity(user: User, state: AppState) -> int:
    if not _ID_PATTERN.fullmatch(user.uuid) or len(user.uuid) > 128:
        raise ValueError("invalid HydraBox subscription_id")
    if (
        type(state.revision) is not int
        or not 0 <= state.revision <= _MAX_STATE_REVISION
    ):
        raise ValueError("invalid HydraBox sequence")
    return (state.revision << _PAYLOAD_REVISION_BITS) | _HYDRABOX_PAYLOAD_REVISION


def _append_plugin_profiles(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
    *,
    resources: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    profile_ids: set[str],
    required_core_features: set[str],
) -> None:
    for plugin in plugins.enabled_transports(state):
        if not plugin.meta.capabilities.hydra_v2_subscription_enabled:
            continue
        try:
            payload = plugins.singbox_client_config(plugin, user, state, apply_name=False)
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
        if not entrypoints:
            continue
        label = resolve_configuration_name(
            key=plugin.meta.name,
            default=plugin.meta.subscription_profile_name or plugin.meta.display_name or plugin.meta.name,
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        )
        multiple = len(entrypoints) > 1
        resource_id = hydrabox_resource_id(plugin.meta.name)
        document: dict[str, list[dict[str, Any]]] = {}
        for section, item in objects:
            document.setdefault(section, []).append(item)
            if item.get("type") == "call":
                required_core_features.add("call")
                if item.get("platform") == "vk" and item.get("mode") == "vk_parasite":
                    required_core_features.add("call_vk_parasite")
        resources.append({
            "id": resource_id,
            "format": "sing-box-json",
            "requested_permissions": _requested_permissions(objects),
            "document": document,
        })
        for section, tag in entrypoints:
            profile_id = hydrabox_profile_id(plugin.meta.name, section, tag)
            if profile_id in profile_ids:
                raise ValueError(f"duplicate HydraBox profile id: {profile_id}")
            profile_ids.add(profile_id)
            profiles.append({
                "id": profile_id,
                "resource": resource_id,
                "name": hydrabox_profile_name(
                    plugin.meta.name, section, tag, objects, label, multiple, state, user,
                ),
                "entrypoint": {"section": section, "tag": tag},
                "enabled": True,
            })


def _append_node_export_profiles(
    node_profiles: tuple[NodeSubscriptionProfile, ...],
    *,
    resources: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    profile_ids: set[str],
    required_core_features: set[str],
) -> None:
    for node_profile in node_profiles:
        for index, projection in enumerate(node_profile.singbox):
            try:
                _validate_depth(projection)
                objects = _runtime_objects(projection)
                entrypoints = _entrypoints(projection, objects)
            except Exception as exc:
                raise ValueError(
                    f"failed to generate {node_profile.protocol} node HydraBox projection",
                ) from exc
            if not entrypoints:
                continue
            resource_key = (
                f"node-{node_profile.node_id}-{node_profile.protocol}-"
                f"{node_profile.profile}-{index}"
            )
            resource_id = hydrabox_resource_id(resource_key)
            document: dict[str, list[dict[str, Any]]] = {}
            for section, item in objects:
                document.setdefault(section, []).append(item)
                if item.get("type") == "call":
                    required_core_features.add("call")
                    if item.get("platform") == "vk" and item.get("mode") == "vk_parasite":
                        required_core_features.add("call_vk_parasite")
            resources.append({
                "id": resource_id,
                "format": "sing-box-json",
                "requested_permissions": _requested_permissions(objects),
                "document": document,
            })
            multiple = len(entrypoints) > 1
            for section, tag in entrypoints:
                profile_id = hydrabox_profile_id(resource_key, section, tag)
                if profile_id in profile_ids:
                    raise ValueError(f"duplicate HydraBox profile id: {profile_id}")
                profile_ids.add(profile_id)
                name = f"{node_profile.name} — {tag}" if multiple else node_profile.name
                profiles.append({
                    "id": profile_id,
                    "resource": resource_id,
                    "name": name,
                    "entrypoint": {"section": section, "tag": tag},
                    "enabled": True,
                })


def generate_hydrabox_subscription(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
    node_exports: ManagedNodeProfileReader | None = None,
) -> dict[str, Any]:
    """Build an activatable plaintext Hydra Subscription v2 document."""
    sequence = _validate_envelope_identity(user, state)
    resources: list[dict[str, Any]] = []
    profiles: list[dict[str, Any]] = []
    profile_ids: set[str] = set()
    required_core_features: set[str] = set()

    _append_plugin_profiles(
        user,
        state,
        plugins,
        resources=resources,
        profiles=profiles,
        profile_ids=profile_ids,
        required_core_features=required_core_features,
    )
    _append_node_export_profiles(
        node_profiles_for_user(user, state, node_exports=node_exports),
        resources=resources,
        profiles=profiles,
        profile_ids=profile_ids,
        required_core_features=required_core_features,
    )
    if not profiles:
        raise ValueError("HydraBox subscription requires an enabled profile")
    if len(profiles) > 4096:
        raise ValueError("HydraBox subscription exceeds the profile limit")
    issued_at = _timestamp(
        user.created_at or "1970-01-01T00:00:00Z",
        "issued_at",
    )
    envelope: dict[str, Any] = {
        "api_version": HYDRABOX_API_VERSION,
        "kind": HYDRABOX_KIND,
        "identity": {
            "issuer": _issuer(user, state),
            "id": user.uuid,
            "channel": "stable",
            "sequence": sequence,
        },
        "validity": {"issued_at": issued_at},
        "display": {"name": {"default": f"HYDRA — {user.email}"}},
        "requirements": {
            "core": {
                "id": "io.hydrabox.hydracore",
                "api_version": 2,
                "remote_policy": 2,
                "features": sorted(required_core_features),
            },
            "client": {
                "subscription_contract": 2,
                "min_version": "0.4.0-beta.1",
                "features": [
                    "automatic-permissions",
                    "multi-resource",
                    "secure-storage",
                    "subscription-jwe",
                ],
            },
        },
        "resources": resources,
        "profiles": profiles,
        "default_profile": profiles[0]["id"],
    }
    if user.expiry_date:
        expires_at = _timestamp(user.expiry_date, "expires_at")
        if _parse_timestamp(expires_at, "expires_at") <= _parse_timestamp(
            issued_at,
            "issued_at",
        ):
            raise ValueError("HydraBox expires_at must be later than issued_at")
        envelope["validity"]["expires_at"] = expires_at
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
