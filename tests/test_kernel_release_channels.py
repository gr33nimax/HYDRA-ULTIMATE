from __future__ import annotations

import pytest

from hydra.services.kernel_release_channels import kernel_release_selection


def test_hydracore_debug_selects_only_debug_prereleases() -> None:
    selection = kernel_release_selection("hydracore", "debug")

    assert selection.include_prerelease is True
    assert selection.prerelease_tag_marker == "-debug."
    assert selection.prerelease_exclude_marker == ""


def test_hydracore_preview_excludes_debug_prereleases() -> None:
    selection = kernel_release_selection("hydracore", "preview")

    assert selection.include_prerelease is True
    assert selection.prerelease_tag_marker == ""
    assert selection.prerelease_exclude_marker == "-debug."


def test_debug_channel_rejects_other_provider() -> None:
    with pytest.raises(ValueError, match="unsupported kernel release channel"):
        kernel_release_selection("sing-box-extended", "debug")
