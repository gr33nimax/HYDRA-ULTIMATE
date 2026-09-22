"""R8/TSK-008: a failed settings change shows its recorded reason.

The generic text exists for a failure whose cause was never recorded; a failure
that recorded a reason must show that reason instead, never the fixed text.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch

from hydra.core.state import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui._menus import mtproto_zig_settings, plugin_settings, settings_support

REASON = "Не удалось применить конфигурацию плагина: route is not active"


def _app(reason: str, *, command_result: bool = False) -> ApplicationService:
    return cast(
        ApplicationService,
        SimpleNamespace(
            admin=SimpleNamespace(load_state=lambda: AppState()),
            plugin_command=Mock(return_value=command_result),
            apply_error=lambda: reason,
        ),
    )


def _naive_state() -> AppState:
    return AppState(
        protocols={"naive": PluginState(enabled=True, config={"network": "tcp"})},
    )


def _naive_domain_change(reason: str) -> list[str]:
    """Run one failed domain change and return the reported errors."""
    errors: list[str] = []
    with (
        patch.object(plugin_settings, "menu", return_value="1"),
        patch.object(plugin_settings, "prompt", return_value="vpn.example.com"),
        patch.object(plugin_settings, "error", errors.append),
    ):
        plugin_settings._menu_naive(_naive_state(), object(), _app(reason))
    return errors


def test_a_failed_change_shows_the_recorded_reason():
    assert _naive_domain_change(REASON) == [REASON]


def test_a_failed_change_without_a_reason_keeps_the_generic_text():
    assert _naive_domain_change("") == [settings_support.FAILURE_TEXT]


def test_a_successful_change_is_reported_as_before():
    successes: list[str] = []
    errors: list[str] = []
    with (
        patch.object(plugin_settings, "menu", return_value="1"),
        patch.object(plugin_settings, "prompt", return_value="vpn.example.com"),
        patch.object(plugin_settings, "success", successes.append),
        patch.object(plugin_settings, "error", errors.append),
    ):
        plugin_settings._menu_naive(_naive_state(), object(), _app(REASON, command_result=True))

    assert successes == ["Домен изменён на vpn.example.com"]
    assert errors == []


def test_the_mtproto_adapter_uses_the_same_shared_reporting():
    errors: list[str] = []

    with patch.object(mtproto_zig_settings, "error", errors.append):
        mtproto_zig_settings._report_change(_app(REASON), False, "не используется")

    assert errors == [REASON]
