"""Read-only manager projections and local relay-profile operations."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path


def external_sources(catalog: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return copy.deepcopy(catalog)


def external_rules_update_due(
    cache: Path,
    *,
    forced: bool = False,
) -> bool:
    """Treat missing, stale, or malformed rule caches as due for refresh."""
    if forced or not cache.exists():
        return True
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
        timestamp = data.get("updated_at") or data.get("last_attempt_at")
        if not timestamp:
            return True
        value = datetime.fromisoformat(str(timestamp))
        now = datetime.now(value.tzinfo) if value.tzinfo else datetime.now()
        threshold = 86400 if data.get("updated_at") else 3600
        return (now - value).total_seconds() >= threshold
    except (OSError, TypeError, ValueError):
        return True


def manager_observation(
    profiles_dir: Path,
    default_profile: Path,
) -> dict[str, object]:
    profiles_dir.mkdir(parents=True, exist_ok=True)
    profiles: list[dict[str, object]] = []
    for path in sorted(profiles_dir.glob("*.conf")):
        is_amnezia = False
        h4_warning = False
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            lowered = content.lower()
            is_amnezia = any(
                key in lowered for key in ("s1", "s2", "jc", "jmin", "jmax")
            )
            match = re.search(r"H4\s*=\s*(\d+)", content, re.IGNORECASE)
            h4_warning = bool(match and int(match.group(1)) > 255)
        except Exception:
            pass
        profiles.append(
            {
                "name": path.stem,
                "is_amnezia": is_amnezia,
                "h4_warning": h4_warning,
            }
        )
    return {
        "default_profile_exists": default_profile.exists(),
        "profile_directory": str(profiles_dir),
        "profiles": profiles,
    }


def delete_local_profile(profiles_dir: Path, *, name: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("invalid WARP profile name")
    path = profiles_dir / f"{name}.conf"
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed


__all__ = [
    "delete_local_profile",
    "external_rules_update_due",
    "external_sources",
    "manager_observation",
]
