"""Pure helpers for converting state models to and from stored documents."""

from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Any, cast, get_type_hints

from hydra.contracts.vless_cdn import DECOY_ROUTE, DECOY_ROUTE_KEY, PROTOCOL_NAME
from hydra.core.state_format import unpack_state_document
from hydra.core.state_migrations import normalize_state_document
from hydra.core.state_models import AppState, validate_raw_state


def to_state_dict(value: Any) -> Any:
    """Recursively turn dataclasses and containers into plain values."""
    if isinstance(value, list):
        return [to_state_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: to_state_dict(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_state_dict(item) for key, item in asdict(value).items()}
    return value


def from_state_dict(model: Any, value: Any) -> Any:
    """Recursively restore typed dataclasses from a plain document."""
    if model is dict:
        return value
    origin = getattr(model, "__origin__", None)
    if origin is list:
        item_model = model.__args__[0]
        return [from_state_dict(item_model, item) for item in value]
    if origin is dict:
        value_model = model.__args__[1]
        return {key: from_state_dict(value_model, item) for key, item in value.items()}
    if hasattr(model, "__dataclass_fields__"):
        try:
            resolved_types = get_type_hints(model)
        except Exception as exc:
            raise ValueError(f"could not resolve state type {model.__name__}: {exc}") from exc
        kwargs = {}
        for key, item in value.items():
            field_type = resolved_types.get(key)
            if field_type is None or item is None and field_type is bool:
                continue
            kwargs[key] = from_state_dict(field_type, item)
        return model(**kwargs)
    return value


def decode_serialized_state(raw: dict) -> dict:
    """Normalize, validate and refresh one encoded persisted state document."""
    document = normalize_state_document(raw)
    decoded = unpack_state_document(document)
    validate_raw_state(cast(dict, decoded))
    _refresh_protocol_routes(decoded)
    return decoded


def _refresh_protocol_routes(raw: dict) -> None:
    protocols = raw.get("protocols")
    if not isinstance(protocols, dict):
        return
    protocol = protocols.get(PROTOCOL_NAME)
    if not isinstance(protocol, dict):
        return
    config = protocol.get("config")
    if isinstance(config, dict) and DECOY_ROUTE_KEY in config:
        config[DECOY_ROUTE_KEY] = copy.deepcopy(DECOY_ROUTE)


__all__ = ["decode_serialized_state", "from_state_dict", "to_state_dict"]
