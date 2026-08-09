from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState, PluginState
from hydra.ui._menus import headless_creator
from hydra.ui.plugin_managers import calls


def test_calls_install_dispatch_uses_injected_application_service() -> None:
    state = AppState()
    operations = SimpleNamespace(
        enable_native_vk=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(calls=operations)

    with patch.object(calls, "_show_result") as show:
        assert calls._dispatch("1", state, app) is True

    operations.enable_native_vk.assert_called_once_with(state)
    show.assert_called_once()


def test_calls_reinstall_dispatch_recreates_room_through_application_service() -> None:
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
    )
    operations = SimpleNamespace(
        reinstall_native_vk=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(calls=operations)

    with (
        patch.object(calls, "confirm", return_value=True),
        patch.object(calls, "_show_result"),
    ):
        assert calls._dispatch("1", state, app) is True

    operations.reinstall_native_vk.assert_called_once_with(state)


def test_calls_uninstall_dispatch_uses_transactional_application_operation() -> None:
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
    )
    operations = SimpleNamespace(
        uninstall_native_vk=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(calls=operations)

    with (
        patch.object(calls, "confirm", return_value=True),
        patch.object(calls, "_show_result", return_value=True),
    ):
        assert calls._dispatch("9", state, app) is False

    operations.uninstall_native_vk.assert_called_once_with(state)


def test_calls_profile_is_only_rendered_after_explicit_confirmation() -> None:
    state = AppState()
    operations = SimpleNamespace(
        native_client_profile=Mock(
            return_value=SimpleNamespace(config='{"secret":"join-link"}'),
        ),
    )
    app = SimpleNamespace(calls=operations)

    with (
        patch.object(calls, "confirm", return_value=False),
        patch("builtins.print") as output,
    ):
        calls._show_profile(state, app)

    operations.native_client_profile.assert_not_called()
    output.assert_not_called()


def test_calls_status_uses_minimal_protocol_panel(monkeypatch) -> None:
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
    )
    app = SimpleNamespace(calls=SimpleNamespace(status=lambda _state: SimpleNamespace(
        native_running=True,
        native_link_ready=True,
    )))
    captured = {}
    monkeypatch.setattr(
        calls,
        "protocol_status_panel",
        lambda *args, **kwargs: captured.update({"args": args, **kwargs}),
    )

    calls._status_panel(state, app)

    assert captured == {
        "args": ("calls",),
        "installed": True,
        "enabled": True,
        "running": True,
        "details": [
            ("Платформа", "VK"),
            ("Режим", "p2p"),
            ("Комната", "создана"),
            ("Комнат в пуле", "0"),
        ],
    }


def test_calls_menu_contains_only_install_or_reinstall_profile_uninstall() -> None:
    assert [option[1] for option in calls._menu_options(installed=False)] == [
        "🔧 Установить",
        "↩ Назад",
    ]
    assert [option[1] for option in calls._menu_options(installed=True)] == [
        "🔄 Переустановить",
        "📄 Показать admin-профиль",
        "🔢 Число VK-комнат",
        "❌ Удалить",
        "↩ Назад",
    ]
    source = Path(calls.__file__).read_text(encoding="utf-8")
    assert "VK cookies" not in source
    assert "Включить" not in source
    assert "Выключить" not in source


def test_calls_tui_has_no_host_or_plugin_runtime_dependencies() -> None:
    path = Path(calls.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Name):
            names.add(node.id)

    assert "hydra.core.host" not in imported
    assert not any(module.startswith("hydra.plugins") for module in imported)
    assert "HOST" not in names
    assert "subprocess" not in names


def test_creator_install_dispatch_uses_independent_application_port() -> None:
    state = AppState()
    operations = SimpleNamespace(
        install=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(headless_creator=operations)

    with patch.object(headless_creator, "_show_result") as show:
        assert headless_creator._dispatch_root("1", state, app) is True

    operations.install.assert_called_once_with(state)
    show.assert_called_once()


def test_creator_root_menu_is_reduced_to_install_qwdtt_uninstall() -> None:
    missing = headless_creator._root_options(installed=False)
    installed = headless_creator._root_options(installed=True)

    assert [option[1] for option in missing] == [
        "🔧 Установить",
        "🎥 qWDTT",
        "↩ Назад",
    ]
    assert [option[1] for option in installed] == [
        "🎥 qWDTT",
        "❌ Удалить",
        "↩ Назад",
    ]


def test_creator_status_shows_provider_marks_real_path_and_room_count(capsys) -> None:
    status = SimpleNamespace(
        installed=True,
        cookies_ready=True,
        cookies_path="/etc/hydra/cookiesvk/cookies-vk.json",
        vk_qwdtt_call_count=3,
        vk_qwdtt_room_count=6,
        legacy_reinstall_required=False,
    )

    headless_creator._root_status_panel(status)

    output = capsys.readouterr().out
    assert "✓ Установлен" in output
    assert "✓ VK" in output and "❌ WB" in output
    assert "/etc/hydra/cookiesvk/cookies-vk.json" in output
    assert "qWDTT rooms: 3/6" in output


def test_creator_status_shows_uninstalled_and_invalid_vk_cookies(capsys) -> None:
    status = SimpleNamespace(
        installed=False,
        cookies_ready=False,
        cookies_path="/etc/hydra/cookiesvk/cookies-vk.json",
        vk_qwdtt_call_count=0,
        vk_qwdtt_room_count=4,
        legacy_reinstall_required=False,
    )

    headless_creator._root_status_panel(status)

    output = capsys.readouterr().out
    assert "❌ Не установлен" in output
    assert "Cookies: ❌ VK  ❌ WB" in output
    assert "qWDTT rooms: 0/4" in output


def test_qwdtt_menu_contains_room_count_action() -> None:
    assert [option[1] for option in headless_creator._qwdtt_options()] == [
        "🎬 Создать комнаты",
        "⏹ Остановить комнаты",
        "🔢 Изменить число комнат",
        "🔄 Включить / выключить автообновление",
        "⏱ Изменить интервал",
        "↩ Назад",
    ]


def test_create_rooms_uses_setup_then_blue_green_refresh() -> None:
    state = AppState()
    operations = SimpleNamespace(
        setup_qwdtt_pool=Mock(return_value=ServiceResult(True)),
        refresh_qwdtt_pool=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(headless_creator=operations)
    fresh = SimpleNamespace(
        vk_qwdtt_pool_enabled=False,
        vk_qwdtt_room_count=2,
        legacy_reinstall_required=False,
    )
    running = SimpleNamespace(
        vk_qwdtt_pool_enabled=True,
        vk_qwdtt_room_count=2,
        legacy_reinstall_required=False,
    )

    with (
        patch.object(headless_creator, "confirm", return_value=True),
        patch.object(headless_creator, "_show_result"),
    ):
        headless_creator._create_rooms(state, app, fresh)
        headless_creator._create_rooms(state, app, running)

    operations.setup_qwdtt_pool.assert_called_once_with(state)
    operations.refresh_qwdtt_pool.assert_called_once_with(state, forced=True)


def test_qwdtt_dispatch_stops_toggles_and_changes_interval() -> None:
    state = AppState()
    status = SimpleNamespace()
    operations = SimpleNamespace(
        stop_qwdtt_pool=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(headless_creator=operations)

    with (
        patch.object(headless_creator, "confirm", return_value=True),
        patch.object(headless_creator, "_show_result"),
        patch.object(headless_creator, "_toggle_auto") as toggle,
        patch.object(headless_creator, "_set_room_count") as room_count,
        patch.object(headless_creator, "_set_interval") as interval,
    ):
        headless_creator._dispatch_qwdtt("2", state, app, status)
        headless_creator._dispatch_qwdtt("3", state, app, status)
        headless_creator._dispatch_qwdtt("4", state, app, status)
        headless_creator._dispatch_qwdtt("5", state, app, status)

    operations.stop_qwdtt_pool.assert_called_once_with(state)
    room_count.assert_called_once_with(state, app)
    toggle.assert_called_once_with(state, app)
    interval.assert_called_once_with(state, app)


def test_creator_tui_has_no_host_or_protocol_plugin_dependency() -> None:
    path = Path(headless_creator.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "hydra.core.host" not in imported
    assert not any(module.startswith("hydra.plugins") for module in imported)
