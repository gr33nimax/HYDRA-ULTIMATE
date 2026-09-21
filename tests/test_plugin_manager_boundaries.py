from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.core.state import AppState, PluginState
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
        menus.menu_plugin(state, plugin, app)  # type: ignore[attr-defined]

    manager.assert_called_once_with(state, app)


def test_menu_dispatch_imports_ui_implementations_not_legacy_facades():
    path = ROOT / "hydra" / "ui" / "_menus" / "plugin_dispatch.py"
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
    assert not any(module.startswith("hydra.plugins.") and module.endswith(".manager") for module in imported_modules)


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
        antidpi.menu_antidpi(state, app)  # type: ignore[arg-type]

    protocols.disable.assert_called_once_with(state, "antidpi")
    protocols.enable.assert_not_called()


def test_telemt_dispatch_ignores_retired_special_menu_keys():
    from hydra.ui.plugin_managers._facade_bridge import bind_facade
    from hydra.ui.plugin_managers import _telemt_menu
    from hydra.ui.plugin_managers import telemt

    with bind_facade(telemt):
        keep_open = _telemt_menu._dispatch(
            "X",
            AppState(),
            SimpleNamespace(),
            SimpleNamespace(enabled=False),
            installed=True,
        )

    assert keep_open is True


class _MenuScript:
    """Return scripted menu choices and record every rendered option list."""

    def __init__(self, choices):
        self._choices = list(choices)
        self.rendered: list[list[tuple[str, str, str]]] = []

    def __call__(self, options, header=""):
        self.rendered.append(list(options))
        return self._choices.pop(0) if self._choices else "0"


def _advanced_state(**advanced) -> tuple[AppState, PluginState]:
    protocol = PluginState(
        enabled=False,
        installed=True,
        config={"settings_version": 1, "port": 8443, "tls_domain": "mask.example", "advanced": dict(advanced)},
    )
    state = AppState()
    state.protocols["telemt"] = protocol
    return state, protocol


def _advanced_app() -> SimpleNamespace:
    return SimpleNamespace(
        admin=SimpleNamespace(save_state=Mock()),
        protocols=SimpleNamespace(reinstall=Mock(return_value=True)),
    )


def _run_advanced(state, app, choices, errors: list[str]) -> list[list[tuple[str, str, str]]]:
    from hydra.ui.plugin_managers._facade_bridge import bind_facade
    from hydra.ui.plugin_managers import _telemt_operations
    from hydra.ui.plugin_managers import telemt

    script = _MenuScript(choices)
    with (
        bind_facade(telemt),
        patch.object(telemt, "menu", script),
        patch.object(telemt, "clear"),
        patch.object(telemt, "success"),
        patch.object(telemt, "error", errors.append),
        patch.object(telemt, "_pause"),
    ):
        _telemt_operations.run_advanced(state, app)
    return script.rendered


def test_telemt_advanced_settings_use_only_bounded_fields():
    state, protocol = _advanced_state(network="auto", use_middle_proxy=False, log_level="normal")
    app = _advanced_app()

    _run_advanced(state, app, ["1", "3", "0"], [])

    assert protocol.config["advanced"] == {
        "network": "ipv6",
        "use_middle_proxy": False,
        "log_level": "normal",
    }
    app.admin.save_state.assert_called_once_with(state)


def test_telemt_advanced_list_shows_three_rows_with_current_values():
    state, _protocol = _advanced_state(network="dual_stack", use_middle_proxy=True, log_level="debug")

    rendered = _run_advanced(state, _advanced_app(), ["0"], [])

    rows = rendered[0]
    assert [key for key, _label, _hint in rows] == ["1", "2", "3", "0"]
    labels = [label for _key, label, _hint in rows]
    assert labels[:3] == [
        "Сеть: dual_stack — слушает 0.0.0.0 и ::",
        "MiddleProxy: on — трафик Telegram идёт через Middle Proxy",
        "Логи: debug — подробная диагностика",
    ]


def test_telemt_advanced_save_changes_one_row_and_returns_to_the_list():
    state, protocol = _advanced_state(network="ipv4", use_middle_proxy=True, log_level="normal")

    rendered = _run_advanced(state, _advanced_app(), ["3", "2", "0"], [])

    assert protocol.config["advanced"] == {
        "network": "ipv4",
        "use_middle_proxy": True,
        "log_level": "debug",
    }
    # The list is rendered again after the save, showing the stored value.
    assert rendered[2][2][1] == "Логи: debug — подробная диагностика"


def test_telemt_advanced_cancel_returns_to_the_list_without_saving():
    state, protocol = _advanced_state(network="ipv4", use_middle_proxy=True, log_level="normal")
    app = _advanced_app()

    rendered = _run_advanced(state, app, ["2", "0", "0"], [])

    assert protocol.config["advanced"] == {"network": "ipv4", "use_middle_proxy": True, "log_level": "normal"}
    app.admin.save_state.assert_not_called()
    assert len(rendered) == 3


def test_telemt_advanced_back_exits_without_persisting():
    state, protocol = _advanced_state(network="ipv4", use_middle_proxy=True, log_level="normal")
    app = _advanced_app()

    rendered = _run_advanced(state, app, ["0"], [])

    assert len(rendered) == 1
    app.admin.save_state.assert_not_called()
    app.protocols.reinstall.assert_not_called()
    assert protocol.config["advanced"] == {"network": "ipv4", "use_middle_proxy": True, "log_level": "normal"}


def test_telemt_advanced_rejects_a_value_outside_the_selected_row():
    state, protocol = _advanced_state(network="ipv4", use_middle_proxy=True, log_level="normal")
    app = _advanced_app()
    errors: list[str] = []

    rendered = _run_advanced(state, app, ["1", "9", "0"], errors)

    # The row offers only its validated values plus the explicit cancel.
    assert [label for _key, label, _hint in rendered[1]] == [
        "auto — слушает 0.0.0.0",
        "ipv4 — слушает 0.0.0.0",
        "ipv6 — слушает ::",
        "dual_stack — слушает 0.0.0.0 и ::",
        "↩ Отмена",
    ]
    assert errors == ["Недопустимое значение для network: 9. Допустимо: auto, ipv4, ipv6, dual_stack"]
    app.admin.save_state.assert_not_called()
    assert protocol.config["advanced"] == {"network": "ipv4", "use_middle_proxy": True, "log_level": "normal"}


def test_telemt_advanced_reapplies_only_while_installed_and_enabled():
    enabled_state, enabled_protocol = _advanced_state(network="ipv4")
    enabled_protocol.enabled = True
    enabled_app = _advanced_app()

    _run_advanced(enabled_state, enabled_app, ["2", "1", "0"], [])

    enabled_app.protocols.reinstall.assert_called_once_with(enabled_state, "telemt")

    idle_app = _advanced_app()
    halted = _advanced_state(network="ipv4")[0]

    _run_advanced(halted, idle_app, ["2", "1", "0"], [])

    idle_app.admin.save_state.assert_called_once_with(halted)
    idle_app.protocols.reinstall.assert_not_called()


def test_telemt_normal_install_has_no_legacy_prompts():
    source = (ROOT / "hydra" / "ui" / "plugin_managers" / "_telemt_operations.py").read_text(encoding="utf-8")
    start = source.index("def run_install")
    normal_flow = source[start : source.index("\ndef run_advanced", start)]

    assert "_choose_network" not in normal_flow
    assert "client_mss" not in normal_flow
    assert "fallback" not in normal_flow
    assert "singbox" not in normal_flow
    assert "optimizations" not in normal_flow


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
            elif isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                violations.append(
                    f"{path.name}:{node.lineno} {ast.unparse(node.value)}.{node.attr}",
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
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)} {module}")

    assert violations == []


def test_entire_plugin_layer_only_reaches_ui_through_legacy_manager_aliases():
    violations: list[str] = []
    plugin_root = ROOT / "hydra" / "plugins"
    allowed = {plugin_root / name / "manager.py" for name in MANAGERS}
    for path in sorted(plugin_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if (module == "hydra.ui" or module.startswith("hydra.ui.")) and path not in allowed:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{getattr(node, 'lineno', 0)} {module}",
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
