"""Map persisted kernel channels to fail-closed GitHub release selection."""
from __future__ import annotations

from dataclasses import dataclass

from hydra.core.state_kernel_models import KERNEL_HYDRACORE


HYDRACORE_DEBUG_TAG_MARKER = "-debug."


@dataclass(frozen=True)
class KernelReleaseSelection:
    include_prerelease: bool = False
    prerelease_tag_marker: str = ""
    prerelease_exclude_marker: str = ""


def kernel_release_selection(
    provider: str,
    channel: str,
) -> KernelReleaseSelection:
    """Return the exact release selector for a validated kernel channel."""
    if channel == "stable":
        return KernelReleaseSelection()
    if channel == "preview":
        return KernelReleaseSelection(
            include_prerelease=True,
            prerelease_exclude_marker=(
                HYDRACORE_DEBUG_TAG_MARKER
                if provider == KERNEL_HYDRACORE
                else ""
            ),
        )
    if channel == "debug" and provider == KERNEL_HYDRACORE:
        return KernelReleaseSelection(
            include_prerelease=True,
            prerelease_tag_marker=HYDRACORE_DEBUG_TAG_MARKER,
        )
    raise ValueError(f"unsupported kernel release channel: {provider}/{channel}")


__all__ = [
    "HYDRACORE_DEBUG_TAG_MARKER",
    "KernelReleaseSelection",
    "kernel_release_selection",
]
