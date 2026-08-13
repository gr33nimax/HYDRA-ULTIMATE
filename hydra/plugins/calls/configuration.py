"""Compatibility exports for the dependency-neutral Calls configuration."""
from hydra.contracts.calls_configuration import (
    CALL_MODE_VK_PARASITE,
    DEFAULT_CALL_PORT,
    DEFAULT_PEER_READ_QUEUE_PACKETS,
    DEFAULT_ROOM_COUNT,
    MAX_JOIN_LINKS,
    MAX_WORKERS,
    CallsStateAccess,
    CallsUser,
    call_mode,
    vk_parasite_inbound as _vk_parasite_inbound,
    vk_parasite_outbound as _vk_parasite_outbound,
    peer_read_queue_packets,
    public_endpoint,
)
from hydra.core.calls_credentials import user_password
from hydra.utils.net import public_ip


def vk_parasite_inbound(state: CallsStateAccess) -> dict:
    return _vk_parasite_inbound(state, user_password)


def vk_parasite_outbound(
    user: CallsUser,
    state: CallsStateAccess,
    join_links: list[str],
) -> dict:
    server_address = public_endpoint(state, public_ip)
    return _vk_parasite_outbound(
        user,
        state,
        join_links,
        user_password,
        server_address=server_address,
    )


__all__ = [
    "CALL_MODE_VK_PARASITE",
    "DEFAULT_CALL_PORT",
    "DEFAULT_PEER_READ_QUEUE_PACKETS",
    "DEFAULT_ROOM_COUNT",
    "MAX_JOIN_LINKS",
    "MAX_WORKERS",
    "call_mode",
    "vk_parasite_inbound",
    "vk_parasite_outbound",
    "peer_read_queue_packets",
    "public_endpoint",
    "user_password",
]
