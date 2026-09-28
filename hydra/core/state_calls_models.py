"""Semantic desired-state invariants for native VK-parasite Calls."""
from __future__ import annotations

from hydra.contracts.calls_configuration import pool_refresh_interval
from hydra.core.state_kernel_models import KERNEL_HYDRACORE


def validate_calls_protocol(
    name: str,
    *,
    enabled: bool,
    config: dict,
    kernel_provider: str,
) -> None:
    if name != "calls":
        return
    if config.get("mode", "vk_parasite") != "vk_parasite":
        raise ValueError("Calls mode must be vk_parasite")
    if enabled and kernel_provider != KERNEL_HYDRACORE:
        raise ValueError("enabled Calls requires the Hydracore kernel")
    pool_refresh_interval(config)


__all__ = ["validate_calls_protocol"]
