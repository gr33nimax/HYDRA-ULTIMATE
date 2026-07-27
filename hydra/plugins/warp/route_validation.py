"""Semantic validation for persisted WARP list-to-outbound assignments."""
from __future__ import annotations

from collections.abc import Mapping


def validate_route_targets(
    list_targets: Mapping[object, object],
    destinations: set[str],
) -> None:
    """Reject unavailable egresses instead of silently leaking them to direct."""
    missing = [
        (str(list_key), str(target))
        for list_key, target in list_targets.items()
        if target and target != "none" and target not in destinations
    ]
    if not missing:
        return
    assignments = ", ".join(
        f"{list_key} -> {target} (not configured)"
        for list_key, target in missing
    )
    raise ValueError(f"Invalid WARP route targets: {assignments}")


__all__ = ["validate_route_targets"]
