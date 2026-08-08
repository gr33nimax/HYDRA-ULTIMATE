from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState
from hydra.ui.plugin_managers import calls
from hydra.ui._menus import headless_creator


def test_calls_menu_dispatch_uses_injected_application_service() -> None:
    state = AppState()
    operations = SimpleNamespace(
        enable_native_vk=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(calls=operations)

    with patch.object(calls, "_show_result") as show:
        assert calls._dispatch("1", state, app) is True

    operations.enable_native_vk.assert_called_once_with(state)
    show.assert_called_once()


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


def test_creator_menu_dispatch_uses_independent_application_port() -> None:
    state = AppState()
    operations = SimpleNamespace(
        install=Mock(return_value=ServiceResult(True)),
    )
    app = SimpleNamespace(headless_creator=operations)

    with patch.object(headless_creator, "_show_result") as show:
        assert headless_creator._dispatch_core("1", state, app) is True

    operations.install.assert_called_once_with(state)
    show.assert_called_once()


def test_creator_root_menu_contains_only_logical_sections() -> None:
    options = headless_creator._root_options()

    assert [option[1] for option in options] == [
        "Creator",
        "VK cookies",
        "qWDTT-комнаты",
        "Назад",
    ]


def test_calls_menu_only_shows_actions_valid_for_current_state() -> None:
    assert [option[1] for option in calls._menu_options(enabled=False)] == [
        "Включить",
        "Назад",
    ]
    assert [option[1] for option in calls._menu_options(enabled=True)] == [
        "Обновить комнату",
        "Показать профиль",
        "Отключить",
        "Назад",
    ]


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
