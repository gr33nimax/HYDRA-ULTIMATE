"""Validation of persisted device bindings, shared by both state checks."""
from __future__ import annotations

from typing import Any


def validate_device_map(devices: Any, *, legacy: bool) -> None:
    """Reject device bindings that are not id -> record mappings.

    Schema 5 turned the binding timestamp into a record describing the
    device, so a migration step still validates the shape it wrote.
    """
    if not isinstance(devices, dict) or any(
        not isinstance(device_id, str) for device_id in devices
    ):
        raise ValueError("user device bindings must be keyed by id")
    expected: Any = (str, dict) if legacy else dict
    if any(not isinstance(record, expected) for record in devices.values()):
        raise ValueError("user device bindings must map ids to records")
    if any(
        not isinstance(value, str)
        for record in devices.values()
        if isinstance(record, dict)
        for value in record.values()
    ):
        raise ValueError("device record fields must be strings")


__all__ = ["validate_device_map"]
