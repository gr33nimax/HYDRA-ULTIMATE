from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.core.state import AppState
from hydra.ui import menus


ROOT = Path(__file__).parents[1]
MANAGERS = (
    "antidpi",
    "dnscrypt",
    "fail2ban",
    "honeypot",
    "ipban",
    "telemt",
    "warp",
    "wdtt",
)


@pytest.mark.parametrize("name", MANAGERS)
def test_legacy_plugin_manager_path_aliases_ui_implementation(name):
    legacy = __import__(
        f"hydra.plugins.{name}.manager",
        fromlist=["manager"],
    )
    implementation = __import__(
        f"hydra.ui.plugin_managers.{name}",
        fromlist=[name],
    )

    assert legacy is implementation


@pytest.mark.parametrize("name", MANAGERS)
def test_plugin_manager_entrypoint_requires_application_service(name):
    implementation = __import__(
        f"hydra.ui.plugin_managers.{name}",
        fromlist=[name],
    )
    parameters = inspect.signature(
        getattr(implementation, f"menu_{name}"),
    ).parameters

    assert list(parameters) == ["state", "app"]
    assert parameters["app"].default is inspect.Parameter.empty


@pytest.mark.parametrize("name", MANAGERS)
def test_menu_dispatch_passes_injected_application(name):
    state = AppState()
    app = SimpleNamespace()
    plugin = SimpleNamespace(meta=SimpleNamespace(name=name))

    with patch(
        f"hydra.ui.plugin_managers.{name}.menu_{name}",
    ) as manager:
        menus.menu_plugin(state, plugin, app)

    manager.assert_called_once_with(state, app)


def test_menu_dispatch_imports_ui_implementations_not_legacy_facades():
    path = (
        ROOT / "hydra" / "ui" / "_menus" / "plugin_dispatch.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    ui_managers: set[str] = set()
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
            if node.module == "hydra.ui.plugin_managers":
                ui_managers.update(alias.name for alias in node.names)

    assert set(MANAGERS) <= ui_managers
    assert not any(
        module.startswith("hydra.plugins.") and module.endswith(".manager")
        for module in imported_modules
    )


def test_antidpi_toggle_delegates_lifecycle_to_application_protocols():
    from hydra.ui.plugin_managers import antidpi

    state = AppState()
    protocols = SimpleNamespace(
        status=Mock(
            side_effect=[
                SimpleNamespace(running=True, info={}),
                SimpleNamespace(running=False, info={}),
            ],
        ),
        health=Mock(return_value=SimpleNamespace(healthy=True)),
        disable=Mock(return_value=True),
        enable=Mock(return_value=True),
    )
    app = SimpleNamespace(
        protocols=protocols,
        plugin_query=Mock(
            return_value={"banned": {}, "history": [], "whitelist": []},
        ),
    )

    with (
        patch.object(antidpi, "menu", side_effect=["1", "0"]),
        patch.object(antidpi, "prompt"),
        patch.object(antidpi, "clear"),
        patch.object(antidpi, "panel"),
        patch.object(antidpi, "success"),
    ):
        antidpi.menu_antidpi(state, app)

    protocols.disable.assert_called_once_with(state, "antidpi")
    protocols.enable.assert_not_called()


def test_telemt_dispatch_accepts_uppercase_special_menu_keys():
    from hydra.ui.plugin_managers._facade_bridge import bind_facade
    from hydra.ui.plugin_managers import _telemt_menu
    from hydra.ui.plugin_managers import telemt

    state = AppState()
    app = SimpleNamespace()
    protocol = SimpleNamespace(enabled=False)

    with (
        bind_facade(telemt),
        patch.object(telemt, "_menu_singbox_integration") as handler,
    ):
        keep_open = _telemt_menu._dispatch(
            "X",
            state,
            app,
            protocol,
            installed=True,
        )

    assert keep_open is True
    handler.assert_called_once_with(state, app)


def test_plugin_manager_layer_has_no_infrastructure_or_private_plugin_calls():
    forbidden_modules = {
        "hydra.core.host",
        "hydra.plugins.management",
        "hydra.plugins.registry",
    }
    violations: list[str] = []

    for name in MANAGERS:
        path = ROOT / "hydra" / "ui" / "plugin_managers" / f"{name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_modules:
                        violations.append(f"{path.name}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in forbidden_modules:
                    violations.append(f"{path.name}:{node.lineno} {node.module}")
            elif isinstance(node, ast.Name) and node.id in {
                "HOST",
                "production_application",
                "save_state",
            }:
                violations.append(f"{path.name}:{node.lineno} {node.id}")
            elif (
                isinstance(node, ast.Attribute)
                and node.attr.startswith("_")
            ):
                violations.append(
                    f"{path.name}:{node.lineno} "
                    f"{ast.unparse(node.value)}.{node.attr}",
                )

    assert violations == []


def test_plugin_implementations_do_not_import_ui_layer():
    violations: list[str] = []
    for name in MANAGERS:
        path = ROOT / "hydra" / "plugins" / name / "plugin.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module == "hydra.ui" or module.startswith("hydra.ui."):
                    violations.append(f"{path.name}:{node.lineno} {module}")

    assert violations == []


def test_entire_plugin_layer_only_reaches_ui_through_legacy_manager_aliases():
    violations: list[str] = []
    plugin_root = ROOT / "hydra" / "plugins"
    allowed = {
        plugin_root / name / "manager.py"
        for name in MANAGERS
    }
    for path in sorted(plugin_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if (
                    module == "hydra.ui"
                    or module.startswith("hydra.ui.")
                ) and path not in allowed:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} {module}",
                    )
    assert violations == []


def test_legacy_manager_files_are_thin_documented_aliases():
    for name in MANAGERS:
        path = ROOT / "hydra" / "plugins" / name / "manager.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        assert len(source.splitlines()) < 15
        assert not any(
            isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            )
            for node in tree.body
        )
