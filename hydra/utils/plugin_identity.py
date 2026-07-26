"""Stable, side-effect-free identifiers shared across application layers."""
from __future__ import annotations

import hashlib

from hydra.core.state_models import User


def snell_user_tag(user: User) -> str:
    """Return the stable inbound tag used to attribute Snell traffic."""
    digest = hashlib.sha256(user.uuid.encode()).hexdigest()[:12]
    return f"snell-{digest}-in"
