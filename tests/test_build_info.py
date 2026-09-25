import importlib
import json

import pytest
import hydra.build_info as build_info
from hydra.ui import tui


def test_build_info_defaults_to_local_when_no_stamp_exists(monkeypatch, tmp_path):

    monkeypatch.setattr(build_info, "BUILD_INFO_PATH", tmp_path / "missing.json")

    assert build_info.get_build_info() == build_info.BuildInfo(channel="local", revision=None)


@pytest.mark.parametrize("channel", ("main", "dev", "debug"))
def test_build_info_reads_only_official_channels(monkeypatch, tmp_path, channel):
    path = tmp_path / "build-info.json"
    path.write_text(json.dumps({"channel": channel, "revision": "a" * 40}), encoding="utf-8")
    monkeypatch.setattr(build_info, "BUILD_INFO_PATH", path)

    assert build_info.get_build_info() == build_info.BuildInfo(channel=channel, revision="a" * 40)


def test_build_info_rejects_unknown_channel_and_revision(monkeypatch, tmp_path):
    path = tmp_path / "build-info.json"
    path.write_text(json.dumps({"channel": "feature/test", "revision": "not-a-sha"}), encoding="utf-8")
    monkeypatch.setattr(build_info, "BUILD_INFO_PATH", path)

    assert build_info.get_build_info() == build_info.BuildInfo(channel="local", revision=None)


@pytest.mark.parametrize("channel", ("main", "dev", "debug"))
def test_banner_displays_the_stamped_channel_and_revision(monkeypatch, tmp_path, channel):
    path = tmp_path / "build-info.json"
    path.write_text(json.dumps({"channel": channel, "revision": "b" * 40}), encoding="utf-8")

    with monkeypatch.context() as patch:
        patch.setattr(build_info, "BUILD_INFO_PATH", path)
        importlib.reload(tui)
        assert f"{channel} · {'b' * 7}" in tui.BANNER
    importlib.reload(tui)
