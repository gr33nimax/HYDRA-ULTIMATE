"""Transport-neutral user entitlement and access policy."""
from __future__ import annotations

from datetime import datetime, timezone

from hydra.core.state_models import User


def entitlement_status(user: User) -> tuple[bool, str]:
    """Check expiry and quota independently from manual blocking."""
    if user.expiry_date:
        try:
            expiry_value = user.expiry_date
            if expiry_value.endswith("Z"):
                expiry_value = f"{expiry_value[:-1]}+00:00"
            expiry = datetime.fromisoformat(expiry_value)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                return False, "срок истёк"
        except (TypeError, ValueError):
            return False, "ошибка даты"

    if user.traffic_limit_gb:
        limit_bytes = int(user.traffic_limit_gb * 1073741824)
        if user.traffic_used_bytes >= limit_bytes:
            return False, "лимит исчерпан"

    return True, "активен"


def access_status(user: User) -> tuple[bool, str]:
    """Return whether a user may connect and the effective reason."""
    if user.blocked:
        entitled, reason = entitlement_status(user)
        return False, reason if not entitled else "заблокирован"
    return entitlement_status(user)


def has_access(user: User) -> bool:
    return access_status(user)[0]


__all__ = ["access_status", "entitlement_status", "has_access"]
