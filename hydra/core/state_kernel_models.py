"""Pure desired-state model for the managed Sing-Box kernel distribution."""
from __future__ import annotations

from dataclasses import dataclass


KERNEL_SINGBOX_EXTENDED = "sing-box-extended"
KERNEL_HYDRACORE = "hydracore"
SUPPORTED_KERNEL_PROVIDERS = frozenset({
    KERNEL_SINGBOX_EXTENDED,
    KERNEL_HYDRACORE,
})
SUPPORTED_KERNEL_CHANNELS = frozenset({"stable", "preview", "debug"})


@dataclass
class KernelConfig:
    """Persisted kernel selection; observed binary facts are never stored here."""

    provider: str = KERNEL_SINGBOX_EXTENDED
    channel: str = "stable"


def validate_raw_kernel_config(raw: object) -> None:
    if not isinstance(raw, dict):
        raise ValueError("state field 'kernel' must be an object")
    _validate_values(raw.get("provider", KERNEL_SINGBOX_EXTENDED), raw.get("channel", "stable"))


def validate_kernel_config(config: KernelConfig) -> None:
    _validate_values(config.provider, config.channel)


def _validate_values(provider: object, channel: object) -> None:
    if not isinstance(provider, str) or provider not in SUPPORTED_KERNEL_PROVIDERS:
        choices = ", ".join(sorted(SUPPORTED_KERNEL_PROVIDERS))
        raise ValueError(f"kernel provider must be one of: {choices}")
    if not isinstance(channel, str) or channel not in SUPPORTED_KERNEL_CHANNELS:
        choices = ", ".join(sorted(SUPPORTED_KERNEL_CHANNELS))
        raise ValueError(f"kernel channel must be one of: {choices}")
    if channel == "debug" and provider != KERNEL_HYDRACORE:
        raise ValueError("kernel debug channel is available only for hydracore")


__all__ = [
    "KERNEL_HYDRACORE",
    "KERNEL_SINGBOX_EXTENDED",
    "KernelConfig",
    "SUPPORTED_KERNEL_CHANNELS",
    "SUPPORTED_KERNEL_PROVIDERS",
    "validate_kernel_config",
    "validate_raw_kernel_config",
]
