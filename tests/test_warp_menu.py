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
from hydra.ui.plugin_managers._facade_bridge import bind_facade
from hydra.ui.plugin_managers import warp as warp_facade
from hydra.ui.plugin_managers._warp_local_lists import _menu_manage_local_list_items, _menu_rules_lists
from hydra.ui.plugin_managers._warp_profiles import _menu_geo_profiles
from hydra.ui.plugin_managers._warp_routing import (
    _category_row,
    _choose_target,
    _filter_sources,
    _target_label,
)


def test_a_source_can_be_found_by_name():
    sources = [
        ("ext:netflix", "Netflix"),
        ("ext:youtube", "YouTube"),
        ("ext:rutracker", "RuTracker"),
    ]

    assert _filter_sources(sources, "youtube") == [("ext:youtube", "YouTube")]
    assert _filter_sources(sources, "tracker") == [("ext:rutracker", "RuTracker")]
    assert _filter_sources(sources, "ext:netflix") == [("ext:netflix", "Netflix")]
    assert _filter_sources(sources, "") == sources
    assert _filter_sources(sources, "нет-такого") == []


def test_failed_apply_restores_deleted_local_list_and_target():
    ps = PluginState(
        enabled=True,
        config={
            "local_lists": {"mine": {"domains": ["example.com"], "ips": []}},
            "list_targets": {"local:mine": "warp"},
        },
    )
    state = AppState(protocols={"warp": ps})
    app = SimpleNamespace(admin=SimpleNamespace(save_state=MagicMock()), apply=MagicMock(return_value=False))
    with (
        bind_facade(warp_facade),
        patch.object(warp_facade, "_external_sources", return_value={}),
        patch("hydra.ui.plugin_managers._warp_local_lists.menu", side_effect=["3", "1", "0"]),
        patch("hydra.ui.plugin_managers._warp_local_lists.confirm", return_value=True),
        patch("hydra.ui.plugin_managers._warp_local_lists.prompt"),
        patch("hydra.ui.plugin_managers._warp_local_lists.panel"),
        patch("hydra.ui.plugin_managers._warp_local_lists.clear"),
        patch("hydra.ui.plugin_managers._warp_local_lists.success"),
        patch("hydra.ui.plugin_managers._warp_local_lists.error"),
    ):
        _menu_rules_lists(state, ps, cast(ApplicationService, app))
    assert "mine" in cast(dict, ps.config["local_lists"])
    assert cast(dict, ps.config["list_targets"])["local:mine"] == "warp"


def test_failed_apply_restores_local_list_before_next_edit():
    ps = PluginState(
        enabled=True,
        config={
            "local_lists": {"mine": {"domains": ["example.com"], "ips": []}},
            "list_targets": {"local:mine": "warp"},
        },
    )
    state = AppState(protocols={"warp": ps})
    app = SimpleNamespace(admin=SimpleNamespace(save_state=MagicMock()), apply=MagicMock(return_value=False))
    with (
        bind_facade(warp_facade),
        patch("hydra.ui.plugin_managers._warp_local_lists.menu", side_effect=["1", "0"]),
        patch("hydra.ui.plugin_managers._warp_local_lists.prompt", side_effect=["new.example.com", ""]),
        patch("hydra.ui.plugin_managers._warp_local_lists.panel"),
        patch("hydra.ui.plugin_managers._warp_local_lists.clear"),
        patch("hydra.ui.plugin_managers._warp_local_lists.success"),
        patch("hydra.ui.plugin_managers._warp_local_lists.error"),
    ):
        _menu_manage_local_list_items(state, ps, "mine", cast(ApplicationService, app))
    assert cast(dict, ps.config["local_lists"])["mine"]["domains"] == ["example.com"]


def test_relay_with_active_routes_cannot_be_deleted_and_silently_sent_direct():
    state = AppState(
        protocols={"warp": PluginState(enabled=True, config={"list_targets": {"local:mylist": "warp_finland"}})}
    )
    app = SimpleNamespace(
        plugin_action=MagicMock(), apply=MagicMock(return_value=True), admin=SimpleNamespace(save_state=MagicMock())
    )
    with (
        bind_facade(warp_facade),
        patch.object(
            warp_facade,
            "_warp_observation",
            return_value={
                "profile_directory": "/tmp",
                "profiles": [{"name": "finland"}],
            },
        ),
        patch("hydra.ui.plugin_managers._warp_profiles.menu", side_effect=["1", "1", "0"]),
        patch("hydra.ui.plugin_managers._warp_profiles.confirm", return_value=True),
        patch("hydra.ui.plugin_managers._warp_profiles.panel"),
        patch("hydra.ui.plugin_managers._warp_profiles.clear"),
        patch("hydra.ui.plugin_managers._warp_profiles.prompt"),
        patch("hydra.ui.plugin_managers._warp_profiles.error"),
    ):
        _menu_geo_profiles(state, state.protocols["warp"], cast(ApplicationService, app))
    app.plugin_action.assert_not_called()
    assert cast(dict, state.protocols["warp"].config["list_targets"])["local:mylist"] == "warp_finland"


def test_route_picker_has_only_destinations_and_cancel():
    with bind_facade(warp_facade), patch("hydra.ui.plugin_managers._warp_routing.menu", return_value="3") as menu:
        assert _choose_target(["direct", "warp"], "route") is None
    assert [option[1] for option in menu.call_args.args[0]] == ["direct", "warp", "Отмена"]


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
        "6",
        "-",
        "8",
        "9",
        "0",
    ]
    assert "Выключить" in labels["1"]
    assert "Сервер подключения WARP" in labels["4"]
    assert labels["8"] == "🔄 Переустановить"
    assert labels["9"] == "❌ Удалить"


def test_masque_menu_is_reachable_from_warp_manager():
    state = AppState(protocols={"warp": PluginState(installed=True)})
    app = _app()
    with bind_facade(warp_facade), patch.object(warp_facade, "_menu_masque") as picker:
        _dispatch("4", state, app, state.protocols["warp"], _status(installed=True), ["direct", "warp"])
    picker.assert_called_once_with(state, app)


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
