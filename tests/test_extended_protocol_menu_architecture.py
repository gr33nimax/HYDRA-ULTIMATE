from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import PluginStatus
from hydra.ui import menus


ROOT = Path(__file__).parents[1]
MENU_ROOT = ROOT / "hydra" / "ui" / "_menus"


def _functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_extended_protocol_facade_is_thin_and_protocol_logic_is_partitioned():
    expected = {
        "extended_protocol_common.py": {
            "_application",
            "_apply_error_text",
            "_desired_state",
            "_show_plugin_clients",
        },
        "extended_protocol_awg.py": {
            "_menu_amneziawg",
            "_tune_awg_hardware",
        },
        "extended_protocol_awg_profiles.py": {
            "_awg_generate_wizard_menu",
            "_manage_awg_profiles",
            "_rotate_awg_obfuscation",
        },
        "extended_protocol_awg_wizard.py": {"_awg_generate_wizard"},
        "extended_protocol_mieru.py": {
            "_menu_mieru",
            "_menu_mieru_obfuscation",
        },
        "extended_protocol_anytls.py": {
            "_menu_anytls",
            "_menu_anytls_obfuscation",
        },
        "extended_protocol_trusttunnel.py": {"_menu_trusttunnel"},
    }

    facade = MENU_ROOT / "extended_protocols.py"
    assert len(facade.read_text(encoding="utf-8").splitlines()) < 150
    assert _functions(facade) == {"_bind", "_make_forwarder"}
    for filename, functions in expected.items():
        path = MENU_ROOT / filename
        assert path.is_file()
        assert len(path.read_text(encoding="utf-8").splitlines()) < 220
        assert _functions(path) == functions


def test_protocol_controllers_do_not_depend_on_unrelated_protocol_menus():
    protocol_modules = {
        "extended_protocol_anytls.py": "extended_protocol_anytls",
        "extended_protocol_mieru.py": "extended_protocol_mieru",
        "extended_protocol_trusttunnel.py": "extended_protocol_trusttunnel",
    }
    violations: list[str] = []
    for filename, own_module in protocol_modules.items():
        tree = ast.parse((MENU_ROOT / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if (
                node.module.startswith("hydra.ui._menus.extended_protocol_")
                and node.module
                not in {
                    "hydra.ui._menus.extended_protocol_common",
                    f"hydra.ui._menus.{own_module}",
                }
            ):
                violations.append(f"{filename}:{node.lineno} {node.module}")

    assert violations == []


def test_legacy_facade_propagates_menu_and_nested_helper_monkeypatches(
    monkeypatch,
):
    state = AppState(
        protocols={
            "anytls": PluginState(installed=True, enabled=True),
        },
    )
    plugin = MagicMock()
    plugin.meta.name = "anytls"
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.protocols.status.return_value = PluginStatus(
        installed=True,
        enabled=True,
        running=True,
        port=443,
    )
    app.plugin_query.return_value = "web_browsing"
    choices = iter(("3", "0"))
    nested = MagicMock()

    monkeypatch.setattr(menus, "clear", MagicMock())
    monkeypatch.setattr(menus, "protocol_status_panel", MagicMock())
    monkeypatch.setattr(menus, "menu", lambda *_args: next(choices))
    monkeypatch.setattr(
        menus,
        "_menu_anytls_obfuscation",
        nested,
    )

    menus._menu_anytls(state, plugin, app)

    nested.assert_called_once_with(state, plugin, app)
