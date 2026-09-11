"""Pure desired-state model for the managed Sing-Box kernel distribution."""
from __future__ import annotations

from dataclasses import dataclass


KERNEL_HYDRACORE = "hydracore"
KERNEL_SINGBOX_EXTENDED = "sing-box-extended"  # legacy persisted value only
SUPPORTED_KERNEL_PROVIDERS = frozenset({KERNEL_HYDRACORE})
SUPPORTED_KERNEL_CHANNELS = frozenset({"stable", "preview", "debug"})


@dataclass
class KernelConfig:
    """Persisted kernel selection; observed binary facts are never stored here."""

    provider: str = KERNEL_HYDRACORE
    channel: str = "debug"


def normalize_legacy_kernel(raw: dict) -> None:
    """Normalize the retired provider in a validated legacy state projection."""
    kernel = raw.setdefault("kernel", {})
    if kernel.get("provider") == KERNEL_SINGBOX_EXTENDED:
        kernel["provider"] = KERNEL_HYDRACORE
        kernel["channel"] = "debug"
    else:
        kernel.setdefault("provider", KERNEL_HYDRACORE)
        kernel.setdefault("channel", "debug")


def validate_raw_kernel_config(raw: object) -> None:
    if not isinstance(raw, dict):
        raise ValueError("state field 'kernel' must be an object")
    provider = raw.get("provider", KERNEL_HYDRACORE)
    if provider == KERNEL_SINGBOX_EXTENDED:
        return
    _validate_values(provider, raw.get("channel", "debug"))


def validate_kernel_config(config: KernelConfig) -> None:
    _validate_values(config.provider, config.channel)


def _validate_values(provider: object, channel: object) -> None:
    if not isinstance(provider, str) or provider not in SUPPORTED_KERNEL_PROVIDERS:
        choices = ", ".join(sorted(SUPPORTED_KERNEL_PROVIDERS))
        raise ValueError(f"kernel provider must be one of: {choices}")
    if not isinstance(channel, str) or channel not in SUPPORTED_KERNEL_CHANNELS:
        choices = ", ".join(sorted(SUPPORTED_KERNEL_CHANNELS))
        raise ValueError(f"kernel channel must be one of: {choices}")


__all__ = [
    "KERNEL_HYDRACORE",
    "KERNEL_SINGBOX_EXTENDED",
    "KernelConfig",
    "SUPPORTED_KERNEL_CHANNELS",
    "SUPPORTED_KERNEL_PROVIDERS",
    "normalize_legacy_kernel",
    "validate_kernel_config",
    "validate_raw_kernel_config",
]
