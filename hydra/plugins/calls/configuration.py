"""Compatibility exports for the dependency-neutral Calls configuration."""
from hydra.contracts.calls_configuration import (
    CALL_MODE_MULTI_USER,
    CALL_MULTIPATH_ADAPTIVE,
    CALL_MULTIPATH_LEGACY,
    DEFAULT_MULTIPATH_PROFILE,
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
    multipath_profile,
    public_endpoint,
)
from hydra.core.calls_credentials import user_password
from hydra.utils.net import public_ip


def multi_user_inbound(state: CallsStateAccess) -> dict:
    return _multi_user_inbound(state, user_password)


def multi_user_outbound(
    user: CallsUser,
    state: CallsStateAccess,
    join_links: list[str],
) -> dict:
    server_address = public_endpoint(state, public_ip)
    return _multi_user_outbound(
        user,
        state,
        join_links,
        user_password,
        server_address=server_address,
    )


__all__ = [
    "CALL_MODE_MULTI_USER",
    "CALL_MULTIPATH_ADAPTIVE",
    "CALL_MULTIPATH_LEGACY",
    "DEFAULT_MULTIPATH_PROFILE",
    "DEFAULT_CALL_PORT",
    "DEFAULT_ROOM_COUNT",
    "MAX_JOIN_LINKS",
    "MAX_WORKERS",
    "MAX_WORKERS_PER_JOIN_LINK",
    "call_mode",
    "multi_user_inbound",
    "multi_user_outbound",
    "multipath_profile",
    "public_endpoint",
    "user_password",
]
