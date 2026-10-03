import sys
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import main
from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui._menus.node_emergency import _runtime_lines


def test_managed_node_role_selects_local_diagnostics_before_base_management(monkeypatch):
    menu = __import__("hydra.ui._menus.node_emergency", fromlist=["run_node_emergency_menu"])
    monkeypatch.setattr(main, "_is_managed_node_install", lambda: True)
    monkeypatch.setattr(sys, "argv", ["hydra"])
    with (
        patch("main.check_root"),
        patch("main.check_python"),
        patch("hydra.core.state.load_state"),
        patch("hydra.bootstrap.production_application"),
        patch("hydra.ui.menus.main_menu") as base_menu,
        patch.object(menu, "run_node_emergency_menu") as local_menu,
    ):
        main.main()
    base_menu.assert_not_called()
    local_menu.assert_called_once()


def test_node_emergency_reports_unknown_management_status_without_false_stopped_claim():
    app = cast(Any, SimpleNamespace(
        kernel=SimpleNamespace(status=lambda _state: SimpleNamespace(runtime=SimpleNamespace(running=True))),
        admin=SimpleNamespace(unit_active=lambda _unit: (_ for _ in ()).throw(OSError("unavailable"))),
        apply_error=lambda: "",
        protocols=SimpleNamespace(statuses=lambda _state: {}, list=lambda _category: []),
    ))

    lines = "\\n".join(_runtime_lines(AppState(), cast(ApplicationService, app)))

    assert "нет данных" in lines
    assert "остановлен" not in lines
    assert "Протоколы:" in lines and "не включены" in lines
