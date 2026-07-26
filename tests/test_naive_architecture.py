"""Architecture guards for the modular NaiveProxy plugin."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import hydra.plugins.naive.plugin as facade
from hydra.plugins.naive.plugin import NaivePlugin


ROOT = Path(__file__).parents[1]
NAIVE_ROOT = ROOT / "hydra" / "plugins" / "naive"
MODULE_LIMITS = {
    "plugin.py": 150,
    "constants.py": 60,
    "access_logs.py": 190,
    "access_log_ingestion.py": 190,
    "configuration.py": 240,
    "installation.py": 150,
    "profiles.py": 270,
    "observation.py": 220,
    "runtime.py": 280,
}
OPERATIONAL_METHODS = {
    "apply",
    "client_link",
    "client_links",
    "configure",
    "connected_clients",
    "generate_client_config",
    "install",
    "on_disable",
    "on_enable",
    "recent_connections",
    "rollback",
    "set_transport",
    "snapshot",
    "status",
    "traffic",
    "uninstall",
}


def _tree(name: str) -> ast.Module:
    return ast.parse(
        (NAIVE_ROOT / name).read_text(encoding="utf-8"),
    )


def _called_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def test_naive_facade_and_capability_modules_remain_bounded():
    for name, limit in MODULE_LIMITS.items():
        path = NAIVE_ROOT / name
        assert path.is_file(), name
        assert len(path.read_text(encoding="utf-8").splitlines()) < limit


def test_naive_functions_remain_reviewable_units():
    oversized: list[str] = []
    for path in sorted(NAIVE_ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > 65:
                oversized.append(f"{path.name}:{node.name}={length}")
    assert oversized == []


def test_naive_facade_contains_composition_and_compatibility_only():
    tree = _tree("plugin.py")
    plugin = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "NaivePlugin"
    )
    methods = {
        node.name
        for node in plugin.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert methods.isdisjoint(OPERATIONAL_METHODS)
    assert {
        "_runtime_layout",
        "_host_backend",
        "_download_asset",
        "_verify_binary",
        "_resolve_tls_material",
    } <= methods


def test_naive_capabilities_have_single_cohesive_owners():
    expected = {
        "configure": "hydra.plugins.naive.configuration",
        "set_transport": "hydra.plugins.naive.configuration",
        "generate_client_config": "hydra.plugins.naive.profiles",
        "client_links": "hydra.plugins.naive.profiles",
        "status": "hydra.plugins.naive.observation",
        "recent_connections": "hydra.plugins.naive.access_logs",
        "install": "hydra.plugins.naive.installation",
        "apply": "hydra.plugins.naive.runtime",
    }
    actual = {
        name: inspect.getmodule(getattr(NaivePlugin, name)).__name__
        for name in expected
    }
    assert actual == expected


def test_naive_internal_modules_do_not_reach_ui_services_or_locators():
    forbidden_imports = (
        "hydra.plugins.registry",
        "hydra.services",
        "hydra.ui",
    )
    violations: list[str] = []
    for path in sorted(NAIVE_ROOT.glob("*.py")):
        if path.name in {"__init__.py", "plugin.py"}:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module.startswith(forbidden_imports):
                    violations.append(
                        f"{path.name}:{node.lineno} {module}",
                    )
        for marker in (
            "DEFAULT_INVOKER",
            "load_state",
            "production_application",
        ):
            if marker in source:
                violations.append(f"{path.name}: {marker}")
    assert violations == [], ", ".join(violations)


def test_naive_read_and_render_modules_do_not_mutate_the_host():
    forbidden_calls = {
        "chmod",
        "close_tcp",
        "close_udp",
        "mkdir",
        "open_tcp",
        "open_udp",
        "replace",
        "rmtree",
        "unlink",
        "write_bytes",
        "write_text",
    }
    violations: dict[str, set[str]] = {}
    for name in (
        "access_logs.py",
        "configuration.py",
        "profiles.py",
        "observation.py",
    ):
        found = _called_names(_tree(name)) & forbidden_calls
        if found:
            violations[name] = found
    assert violations == {}


def test_naive_internal_modules_never_import_the_facade():
    violations: list[str] = []
    for path in sorted(NAIVE_ROOT.glob("*.py")):
        if path.name in {"__init__.py", "plugin.py"}:
            continue
        for node in ast.walk(_tree(path.name)):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.endswith("naive.plugin")
            ):
                violations.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.endswith("naive.plugin"):
                        violations.append(f"{path.name}:{node.lineno}")
    assert violations == []


def test_naive_facade_constants_remain_patchable(monkeypatch, tmp_path):
    assert NaivePlugin._runtime_layout().data_dir == Path(
        "/var/lib/caddy-naive",
    )
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    monkeypatch.setattr(facade, "LOG_DIR", log_dir)
    monkeypatch.setattr(facade, "DATA_DIR", data_dir)
    layout = NaivePlugin._runtime_layout()
    assert layout.log_dir == log_dir
    assert layout.data_dir == data_dir
