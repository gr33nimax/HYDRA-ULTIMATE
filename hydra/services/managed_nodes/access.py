"""Faithful user projection across the managed-node boundary."""

from __future__ import annotations

import copy

from hydra.contracts.managed_node_models import UserAssignment
from hydra.core.state_models import User
from hydra.services.user_access import access_status

_RESET_EPOCHS_KEY = "managed_node_user_reset_epochs"


def assignment_from_user(user: User, *, reset_epoch: int) -> UserAssignment:
    allowed, _reason = access_status(user)
    return UserAssignment(
        uuid=user.uuid,
        email=user.email,
        blocked=user.blocked or not allowed,
        expiry_date=user.expiry_date,
        traffic_limit_gb=user.traffic_limit_gb,
        disabled_protocols=list(user.disabled_protocols),
        reset_epoch=reset_epoch,
    )


def user_from_assignment(
    assignment: UserAssignment,
    *,
    previous: User | None,
    state_install: dict,
) -> User:
    """Keep node-generated credentials by UUID; never import base private keys."""
    assignment.validate()
    epochs = state_install.setdefault(_RESET_EPOCHS_KEY, {})
    if not isinstance(epochs, dict):
        raise ValueError("managed-node user reset epochs are invalid")
    previous_epoch = epochs.get(assignment.uuid, 0)
    credentials = copy.deepcopy(previous.credentials) if previous is not None else {}
    traffic_used = previous.traffic_used_bytes if previous is not None else 0
    if previous is not None and previous_epoch != assignment.reset_epoch:
        traffic_used = 0
        for stats in credentials.values():
            if not isinstance(stats, dict):
                continue
            for key in tuple(stats):
                if key.startswith("traffic_") and key != "traffic_last_raw_bytes":
                    stats.pop(key, None)
            stats["traffic_used_bytes"] = 0
    epochs[assignment.uuid] = assignment.reset_epoch
    user = User(
        email=assignment.email,
        uuid=assignment.uuid,
        traffic_limit_gb=assignment.traffic_limit_gb,
        traffic_used_bytes=traffic_used,
        expiry_date=assignment.expiry_date,
        blocked=assignment.blocked,
        created_at=previous.created_at if previous is not None else "",
        telegram_id=previous.telegram_id if previous is not None else None,
        credentials=credentials,
        device_limit=previous.device_limit if previous is not None else 0,
        devices=copy.deepcopy(previous.devices) if previous is not None else {},
        hydrabox_jwe_key=previous.hydrabox_jwe_key if previous is not None else "",
        configuration_name_overrides=copy.deepcopy(previous.configuration_name_overrides) if previous is not None else {},
        disabled_protocols=list(assignment.disabled_protocols),
    )
    return user


__all__ = ["assignment_from_user", "user_from_assignment"]
