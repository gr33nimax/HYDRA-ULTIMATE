from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.kernel_release_channels import (
    KernelReleaseSelection,
    kernel_release_selection,
)
from hydra.utils import downloader


# The published shapes of the readable Hydracore tag contract (design D7).
READABLE_RELEASES = [
    {"tag_name": "hydracore-sbe-1.14.0", "draft": False, "prerelease": False},
    {
        "tag_name": "hydracore-sbe-1.14.0-rc-1",
        "draft": False,
        "prerelease": True,
        "published_at": "2026-09-18T19:39:55Z",
    },
    {
        "tag_name": "hydracore-sbe-1.14.0-debug-1",
        "draft": False,
        "prerelease": True,
        "published_at": "2026-09-18T18:59:20Z",
    },
    {
        "tag_name": "v1.14.0-extended-2.7.1-hydracore.12-debug.11",
        "draft": False,
        "prerelease": True,
        "published_at": "2026-09-18T17:20:03Z",
    },
]


def _latest_for(selection: KernelReleaseSelection, releases: list[dict]) -> str:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(releases).encode()
    with patch.object(downloader.urllib.request, "urlopen", return_value=response):
        return downloader.latest_release(
            "gr33nimax/hydracore",
            include_prerelease=selection.include_prerelease,
            prerelease_tag_markers=selection.prerelease_tag_markers,
            prerelease_exclude_markers=selection.prerelease_exclude_markers,
        )


def test_hydracore_debug_accepts_debug_and_release_candidate_prereleases() -> None:
    selection = kernel_release_selection("hydracore", "debug")

    assert selection.include_prerelease is True
    assert selection.prerelease_tag_markers == ("-debug-", "-rc-")
    assert selection.prerelease_exclude_markers == ("-debug.",)
    assert _latest_for(selection, READABLE_RELEASES) == "hydracore-sbe-1.14.0-rc-1"


def test_hydracore_debug_ignores_the_retired_debug_dot_form() -> None:
    selection = kernel_release_selection("hydracore", "debug")
    retired_only = [
        release
        for release in READABLE_RELEASES
        if release["tag_name"] == "v1.14.0-extended-2.7.1-hydracore.12-debug.11"
    ]

    assert _latest_for(selection, retired_only) == "unknown"


def test_hydracore_preview_resolves_the_legacy_persisted_value() -> None:
    legacy = kernel_release_selection("hydracore", "preview")

    assert legacy == kernel_release_selection("hydracore", "debug")
    assert _latest_for(legacy, READABLE_RELEASES) == "hydracore-sbe-1.14.0-rc-1"


def test_hydracore_stable_keeps_selecting_the_non_prerelease_release() -> None:
    selection = kernel_release_selection("hydracore", "stable")
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"tag_name": "hydracore-sbe-1.14.0", "prerelease": False}
    ).encode()

    with patch.object(downloader.urllib.request, "urlopen", return_value=response) as urlopen:
        tag = downloader.latest_release(
            "gr33nimax/hydracore",
            include_prerelease=selection.include_prerelease,
            prerelease_tag_markers=selection.prerelease_tag_markers,
            prerelease_exclude_markers=selection.prerelease_exclude_markers,
        )

    assert selection == KernelReleaseSelection()
    assert tag == "hydracore-sbe-1.14.0"
    assert str(urlopen.call_args.args[0].full_url).endswith("/releases/latest")


def test_debug_channel_rejects_other_provider() -> None:
    with pytest.raises(ValueError, match="unsupported kernel release channel"):
        kernel_release_selection("sing-box-extended", "debug")
