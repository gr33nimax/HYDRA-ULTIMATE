"""Architecture constraints for the modular monitoring menu."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState
from hydra.ui import menus
from hydra.ui._menus import (
    monitoring,
    monitoring_connections,
    monitoring_logs,
    monitoring_overview,
    monitoring_realtime,
    monitoring_services,
    monitoring_support,
    monitoring_traffic,
)


ROOT = Path(__file__).parents[1]
MODULES = (
    monitoring,
    monitoring_connections,
    monitoring_logs,
    monitoring_overview,
    monitoring_realtime,
    monitoring_services,
    monitoring_support,
    monitoring_traffic,
)
IMPLEMENTATIONS = {
    "_application": monitoring_support,
    "_apply_error_text": monitoring_support,
    "_unit_active": monitoring_support,
    "_unit_known": monitoring_support,
    "_is_enter_pressed": monitoring_support,
    "menu_monitoring": monitoring_overview,
    "_menu_service_settings": monitoring_overview,
    "_show_traffic_combined": monitoring_traffic,
    "_show_connections": monitoring_connections,
    "_show_status": monitoring_realtime,
    "_read_proc_cpu": monitoring_realtime,
    "_read_proc_mem": monitoring_realtime,
    "_read_proc_net": monitoring_realtime,
    "_show_realtime_sys_monitor": monitoring_realtime,
    "_menu_logs": monitoring_logs,
    "_log_source_status": monitoring_logs,
    "_read_log_source": monitoring_logs,
    "_show_log_source": monitoring_logs,
    "_show_log_file": monitoring_logs,
    "_watch_log_file": monitoring_logs,
    "_watch_journal": monitoring_logs,
    "_sync_agent_log_snapshot": monitoring_logs,
    "_menu_sync_agent": monitoring_services,
    "_menu_clash_api": monitoring_services,
}


def test_monitoring_facade_preserves_controller_signatures() -> None:
    for name, implementation in IMPLEMENTATIONS.items():
        assert hasattr(monitoring, name)
        assert inspect.signature(getattr(monitoring, name)) == (
            inspect.signature(getattr(implementation, name))
        )


def test_monitoring_modules_and_functions_are_bounded() -> None:
    violations: list[str] = []
    for module in MODULES:
        path = Path(inspect.getsourcefile(module))
        source = path.read_text(encoding="utf-8")
        if len(source.splitlines()) > 350:
            violations.append(f"{path.relative_to(ROOT)} exceeds 350 lines")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            size = (node.end_lineno or node.lineno) - node.lineno + 1
            if size > 120:
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno} "
                    f"{node.name} has {size} lines",
                )
    assert violations == []


def test_monitoring_facade_contains_no_menu_rendering() -> None:
    source = Path(inspect.getsourcefile(monitoring)).read_text(
        encoding="utf-8",
    )
    tree = ast.parse(source)
    rendered_calls = {
        child.func.id
        for child in ast.walk(tree)
        if isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id in {"menu", "panel", "print", "prompt", "title"}
    }
    assert rendered_calls == set()


def test_facade_monkeypatches_reach_nested_monitoring_controllers() -> None:
    state = AppState()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.admin.unit_active.return_value = False

    with patch.object(menus, "clear"), \
         patch.object(menus, "panel"), \
         patch.object(menus, "menu", side_effect=["1", "0"]), \
         patch.object(menus, "_menu_logs") as menu_logs:
        menus._menu_service_settings(state, app)

    menu_logs.assert_called_once_with(state, app)
