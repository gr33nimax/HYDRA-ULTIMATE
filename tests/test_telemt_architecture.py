"""Architecture and compatibility guards for the modular Telemt package."""
from __future__ import annotations

import ast
import importlib
from pathlib import Path

from hydra.plugins.telemt.plugin import TelemtPlugin

ROOT = Path(__file__).resolve().parents[1]
TELEMT = ROOT / "hydra" / "plugins" / "telemt"
COMPATIBILITY_MODULES = {
    "manager.py",
}
FEATURE_FACADES = {
    "mtproto_stats.py": "mtproto_stats_console",
    "telemt_ios_fix.py": "telemt_ios_fix_console",
    "telemt_syn_limiter.py": "telemt_syn_limiter_console",
    "tg_nets.py": "tg_nets_console",
}


def _production_modules() -> list[Path]:
    return [
        path
        for path in TELEMT.glob("*.py")
        if path.name not in COMPATIBILITY_MODULES
    ]


def test_telemt_modules_and_functions_remain_reviewable() -> None:
    oversized_modules = []
    oversized_functions = []
    for path in _production_modules():
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > 400:
            oversized_modules.append(f"{path.name}={len(lines)}")
        for node in ast.walk(ast.parse("\n".join(lines))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > 100:
                oversized_functions.append(
                    f"{path.name}:{node.name}={length}"
                )
    assert oversized_modules == []
    assert oversized_functions == []


def test_telemt_domain_does_not_reach_services_ui_or_registry() -> None:
    forbidden = (
        "hydra.plugins.registry",
        "hydra.services",
        "hydra.ui",
    )
    violations = []
    for path in _production_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module.startswith(forbidden):
                    violations.append(f"{path.name}:{node.lineno} {module}")
    assert violations == []


def test_feature_entrypoints_remain_compatibility_facades() -> None:
    for facade_name, implementation_name in FEATURE_FACADES.items():
        facade = importlib.import_module(
            f"hydra.plugins.telemt.{facade_name.removesuffix('.py')}"
        )
        implementation = importlib.import_module(
            f"hydra.plugins.telemt.{implementation_name}"
        )
        assert facade is implementation


def test_telemt_plugin_keeps_public_hooks_and_traffic_snapshot() -> None:
    expected = {
        "apply",
        "configure",
        "install",
        "uninstall",
        "status",
        "traffic",
        "traffic_snapshot",
        "client_link",
        "client_links",
        "generate_client_config",
        "snapshot",
        "rollback",
    }
    assert expected <= set(vars(TelemtPlugin))


def test_feature_runtime_modules_do_not_import_console_or_facades() -> None:
    violations = []
    facade_stems = {
        "mtproto_stats",
        "telemt_ios_fix",
        "telemt_syn_limiter",
        "tg_nets",
    }
    for path in TELEMT.glob("*_runtime.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            stem = node.module.rsplit(".", 1)[-1]
            if stem.endswith("_console") or stem in facade_stems:
                violations.append(f"{path.name}:{node.lineno} {node.module}")
    assert violations == []


def test_legacy_feature_private_seams_resolve_at_call_time(
    monkeypatch,
) -> None:
    syn = importlib.import_module("hydra.plugins.telemt.telemt_syn_limiter")
    ios = importlib.import_module("hydra.plugins.telemt.telemt_ios_fix")
    nets = importlib.import_module("hydra.plugins.telemt.tg_nets")

    calls: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        syn,
        "_run",
        lambda command, capture=False: calls.append(command) or Result(),
    )
    monkeypatch.setattr(
        ios,
        "_run",
        lambda command, capture=False: calls.append(command) or Result(),
    )
    monkeypatch.setattr(nets, "_http_get", lambda *_args, **_kwargs: None)

    assert syn._rule_exists() is False
    assert ios._rules_exist() is False
    assert nets._src_ripe_stat([62041]) == ([], 0, "недоступен")
    assert len(calls) == 2
