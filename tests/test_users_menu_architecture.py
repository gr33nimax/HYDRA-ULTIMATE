"""Architecture and compatibility contracts for the user-menu controllers."""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

from hydra.core.state import AppState
from hydra.ui import menus
from hydra.ui._menus import (
    facade_contract,
    users,
    users_links,
    users_management,
    users_overview,
    users_subscription,
)


ROOT = Path(__file__).parents[1]
USER_MODULES = (
    "users.py",
    "users_common.py",
    "users_links.py",
    "users_management.py",
    "users_overview.py",
    "users_subscription.py",
)


def test_user_menu_modules_and_functions_stay_bounded() -> None:
    menu_root = ROOT / "hydra" / "ui" / "_menus"
    for name in USER_MODULES:
        source = (menu_root / name).read_text(encoding="utf-8")
        assert len(source.splitlines()) <= 350, name
        tree = ast.parse(source)
        for function in (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            size = (function.end_lineno or function.lineno) - function.lineno + 1
            assert size <= 120, f"{name}:{function.name} ({size} lines)"


def test_user_facade_keeps_the_historical_symbol_surface() -> None:
    expected = {
        "_add_user",
        "_application",
        "_obtain_cert_for_sub",
        "_reconcile_user_access",
        "_select_user",
        "_show_subscription_links",
        "_show_user_detail",
        "_show_users",
        "_toggle_block",
        "_user_configs",
        "_user_detail_menu",
        "_user_links",
        "install_sub_systemd_service",
        "menu_subscription_server",
        "menu_users",
    }
    assert expected <= set(vars(users))
    assert not [
        node
        for node in ast.parse(
            (ROOT / "hydra" / "ui" / "_menus" / "users.py").read_text(
                encoding="utf-8"
            )
        ).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def test_user_companions_are_part_of_the_menu_monkeypatch_contract() -> None:
    controller, _names, companions = facade_contract.BINDER_SPECS["_user_menus"]
    assert controller is users
    assert companions == (
        users_links,
        users_management,
        users_overview,
        users_subscription,
    )


def test_facade_monkeypatch_reaches_cross_controller_calls(monkeypatch) -> None:
    choices = iter(("1", "0"))
    show_users = MagicMock()
    monkeypatch.setattr(menus, "clear", MagicMock())
    monkeypatch.setattr(menus, "title", MagicMock())
    monkeypatch.setattr(menus, "info", MagicMock())
    monkeypatch.setattr(menus, "menu", lambda *_args: next(choices))
    monkeypatch.setattr(menus, "_show_users", show_users)

    menus.menu_users(AppState(), MagicMock())

    show_users.assert_called_once()
