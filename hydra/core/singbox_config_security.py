"""Redaction helpers for persisted Sing-Box diagnostic artifacts."""
from __future__ import annotations

import copy
from typing import Any


_SENSITIVE_CONFIG_KEYS = frozenset({"cookies", "join_link"})


def redacted_debug_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a diagnostic copy without call credentials or shared links."""
    redacted = copy.deepcopy(config)

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in _SENSITIVE_CONFIG_KEYS:
                    value[key] = "<redacted>"
                else:
                    visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(redacted)
    return redacted


__all__ = ["redacted_debug_config"]
