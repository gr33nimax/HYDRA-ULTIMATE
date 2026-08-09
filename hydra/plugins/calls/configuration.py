"""Compatibility exports for the dependency-neutral Calls configuration."""
from hydra.contracts.calls_configuration import (
    CALL_MODE_MULTI_USER,
    DEFAULT_CALL_PORT,
    DEFAULT_ROOM_COUNT,
    MAX_JOIN_LINKS,
    MAX_WORKERS,
    MAX_WORKERS_PER_JOIN_LINK,
    CallsStateAccess,
    CallsUser,
    call_mode,
    multi_user_inbound as _multi_user_inbound,
    multi_user_outbound as _multi_user_outbound,
)
from hydra.core.calls_credentials import user_password


def multi_user_inbound(state: CallsStateAccess) -> dict:
    return _multi_user_inbound(state, user_password)


def multi_user_outbound(
    user: CallsUser,
    state: CallsStateAccess,
    join_links: list[str],
) -> dict:
    return _multi_user_outbound(user, state, join_links, user_password)


__all__ = [
    "CALL_MODE_MULTI_USER",
    "DEFAULT_CALL_PORT",
    "DEFAULT_ROOM_COUNT",
    "MAX_JOIN_LINKS",
    "MAX_WORKERS",
    "MAX_WORKERS_PER_JOIN_LINK",
    "call_mode",
    "multi_user_inbound",
    "multi_user_outbound",
    "user_password",
]
