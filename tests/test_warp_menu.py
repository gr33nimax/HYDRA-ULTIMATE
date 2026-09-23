from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._warp_menu import (
    _dispatch,
    _options,
    _status_lines,
)
from hydra.ui.plugin_managers._warp_routing import _category_row, _target_label


def test_a_partially_routed_category_names_its_real_coverage():
    assert "1 из 13" in _target_label("warp_Russia", 1, 13)
    assert "выключено" in _target_label("none", 0, 13)
    assert "выключено" in _target_label("none")
    assert "разные" in _target_label("mixed", 3, 5)
    assert "warp" in _target_label("warp", 2, 2)


def test_the_category_row_carries_the_target_and_the_usual_direction():
    row = _category_row(
        {
            "label": "Российские сервисы",
            "target": "warp_Russia",
            "routed": 1,
            "total": 13,
            "direction": "direct",
            "description": "13 источников",
        },
    )

    assert "Российские сервисы" in row
    assert "warp_Russia" in row
    assert "1 из 13" in row
    assert "DIRECT" in row


def _status(installed: bool, enabled: bool = False):
    return SimpleNamespace(
        installed=installed,
        enabled=enabled,
        running=installed and enabled,
    )


def _app(**lifecycle) -> ApplicationService:
    """A stub application service carrying only the calls under test."""
    return cast(
        ApplicationService,
        SimpleNamespace(protocols=SimpleNamespace(**lifecycle)),
    )


def test_options_offer_the_normal_plugin_lifecycle():
    fresh = _options(_status(installed=False))

    assert [key for key, _, _ in fresh] == ["1", "0"]
    assert "Установить" in fresh[0][1]

    installed = _options(_status(installed=True, enabled=True))
    labels = {key: label for key, label, _ in installed}

    assert [key for key, _, _ in installed] == [
        "1",
        "2",
        "3",
        "4",
        "5",
        "-",
        "8",
        "9",
        "0",
    ]
    assert "Выключить" in labels["1"]
    assert labels["8"] == "🔄 Переустановить"
    assert labels["9"] == "❌ Удалить"


def test_an_uninstalled_plugin_installs_from_the_menu():
    state = AppState(protocols={"warp": PluginState()})
    install = MagicMock(return_value=True)
    app = _app(install=install)

    with (
        patch("hydra.ui.plugin_managers._warp_menu.info"),
        patch("hydra.ui.plugin_managers._warp_menu.success"),
        patch("hydra.ui.plugin_managers._warp_menu.prompt"),
    ):
        _dispatch(
            "1",
            state,
            app,
            state.protocols["warp"],
            _status(installed=False),
            ["direct", "warp"],
        )

    install.assert_called_once_with(state, "warp")


def test_an_installed_plugin_reinstalls_and_uninstalls_from_the_menu():
    state = AppState(protocols={"warp": PluginState()})
    reinstall = MagicMock(return_value=True)
    disable = MagicMock(return_value=True)
    uninstall = MagicMock(return_value=True)
    app = _app(reinstall=reinstall, disable=disable, uninstall=uninstall)

    with (
        patch("hydra.ui.plugin_managers._warp_menu.info"),
        patch("hydra.ui.plugin_managers._warp_menu.success"),
        patch("hydra.ui.plugin_managers._warp_menu.warn"),
        patch("hydra.ui.plugin_managers._warp_menu.confirm", return_value=True),
        patch("hydra.ui.plugin_managers._warp_menu.prompt"),
    ):
        _dispatch(
            "8",
            state,
            app,
            state.protocols["warp"],
            _status(installed=True, enabled=True),
            ["direct", "warp"],
        )
        _dispatch(
            "9",
            state,
            app,
            state.protocols["warp"],
            _status(installed=True, enabled=True),
            ["direct", "warp"],
        )

    reinstall.assert_called_once_with(state, "warp")
    disable.assert_called_once_with(state, "warp")
    uninstall.assert_called_once_with(state, "warp")


def test_disabled_status_marks_routes_inactive_and_missing_target_invalid():
    lines = _status_lines(
        SimpleNamespace(installed=True, enabled=False, running=False),
        ["Finland"],
        ["direct", "warp_Finland"],
        {"ext:google_ai": "warp"},
        {"google_ai": {"name": "GoogleAI"}},
    )
    rendered = "\n".join(lines)

    assert "маршруты WARP сейчас не применяются" in rendered
    assert "warp (недоступен)" in rendered
