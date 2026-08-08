"""Compatibility tests for the retired WDTT-owned creator surface."""
from __future__ import annotations

import pytest

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.wdtt import headless
from hydra.plugins.wdtt.plugin import WdttPlugin


def test_legacy_headless_imports_are_non_mutating_forwarders() -> None:
    assert headless.HEADLESS_MAINTENANCE_TASKS == ()
    assert headless.install()[0] is False
    assert headless.setup()[0] is False
    assert headless.stop()[0] is False
    with pytest.raises(RuntimeError, match="ApplicationService.headless_creator"):
        headless.uninstall()


def test_legacy_mixin_is_not_part_of_wdtt_plugin_contract() -> None:
    plugin = WdttPlugin()
    capabilities = plugin.meta.capabilities
    assert not isinstance(plugin, headless.WdttHeadlessMixin)
    assert "setup_headless_creator" not in capabilities.actions
    assert "refresh_headless_creator" not in capabilities.actions
    assert "stop_headless_creator" not in capabilities.actions
    assert "set_headless_refresh_interval" not in capabilities.commands


def test_legacy_refresh_setter_is_a_non_mutating_error_shim() -> None:
    state = AppState(
        protocols={
            "wdtt": PluginState(enabled=True),
            "calls": PluginState(),
        },
    )
    mixin = headless.WdttHeadlessMixin()

    with pytest.raises(RuntimeError, match="ApplicationService.headless_creator"):
        mixin.set_headless_refresh_interval(state=state, seconds=7200)
    assert state.protocols["calls"].config == {}
    assert state.protocols["wdtt"].config == {}


def test_qwdtt_link_builder_still_has_compatibility_import() -> None:
    link = headless.build_qwdtt_link(
        "203.0.113.10",
        56000,
        "master",
        ["a", "b", "c", "d"],
    )
    assert link.startswith("qwdtt://config?")
    assert "hashes=a,b,c,d" in link
