"""Map a persisted kernel channel to a fail-closed GitHub release selection."""

from __future__ import annotations

from dataclasses import dataclass

from hydra.core.state_kernel_models import (
    KERNEL_HYDRACORE,
    resolve_kernel_channel,
)


# Readable Hydracore tag contract: `hydracore-sbe-<sbe-version>` is the stable
# release, while `hydracore-sbe-<sbe-version>-debug-<n>` and
# `hydracore-sbe-<sbe-version>-rc-<n>` are the prereleases the debug channel
# serves. `-debug.<n>` is the retired prerelease form: those releases stay
# immutable on GitHub, so no channel may select them.
HYDRACORE_DEBUG_TAG_MARKERS = ("-debug-", "-rc-")
HYDRACORE_RETIRED_TAG_MARKER = "-debug."


@dataclass(frozen=True)
class KernelReleaseSelection:
    include_prerelease: bool = False
    prerelease_tag_markers: tuple[str, ...] = ()
    prerelease_exclude_markers: tuple[str, ...] = ()


def kernel_release_selection(
    provider: str,
    channel: str,
) -> KernelReleaseSelection:
    """Return the exact release selector for a persisted kernel channel."""
    if channel == "stable":
        return KernelReleaseSelection()
    if provider == KERNEL_HYDRACORE:
        if resolve_kernel_channel(channel) == "debug":
            return KernelReleaseSelection(
                include_prerelease=True,
                prerelease_tag_markers=HYDRACORE_DEBUG_TAG_MARKERS,
                prerelease_exclude_markers=(HYDRACORE_RETIRED_TAG_MARKER,),
            )
    elif channel == "preview":
        # Retired provider value: keep the historical generic prerelease scan.
        return KernelReleaseSelection(include_prerelease=True)
    raise ValueError(f"unsupported kernel release channel: {provider}/{channel}")


__all__ = [
    "HYDRACORE_DEBUG_TAG_MARKERS",
    "HYDRACORE_RETIRED_TAG_MARKER",
    "KernelReleaseSelection",
    "kernel_release_selection",
]
