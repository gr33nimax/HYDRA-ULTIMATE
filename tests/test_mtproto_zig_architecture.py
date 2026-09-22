"""Architecture guards for the modular mtproto_zig package."""

from __future__ import annotations

import ast
from pathlib import Path

from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin

ROOT = Path(__file__).resolve().parents[1]
ZIG = ROOT / "hydra" / "plugins" / "mtproto_zig"
# The WEB extension owns these modules; a rename must not silently drop them
# out of the size guard.
REQUIRED_MODULES = {"bridge_probe.py", "web_runtime.py"}


def _production_modules() -> list[Path]:
    return sorted(ZIG.glob("*.py"))


def test_mtproto_zig_modules_and_functions_remain_reviewable() -> None:
    modules = _production_modules()
    assert REQUIRED_MODULES <= {path.name for path in modules}
    oversized_modules = []
    oversized_functions = []
    for path in modules:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > 400:
            oversized_modules.append(f"{path.name}={len(lines)}")
        for node in ast.walk(ast.parse("\n".join(lines))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > 100:
                oversized_functions.append(f"{path.name}:{node.name}={length}")
    assert oversized_modules == []
    assert oversized_functions == []


def test_mtproto_zig_domain_does_not_reach_services_ui_or_registry() -> None:
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
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)} {module}")
    assert violations == []


def test_mtproto_zig_plugin_keeps_public_hooks_and_web_command() -> None:
    expected = {
        "apply",
        "apply_failure",
        "certificate_requirements",
        "client_link",
        "client_links",
        "configure",
        "finalize_apply",
        "generate_client_config",
        "healthcheck_for_state",
        "install",
        "install_failure",
        "needs_tls_domain",
        "on_disable",
        "on_enable",
        "on_user_add",
        "rollback",
        "set_web_settings",
        "snapshot",
        "status",
        "traffic",
        "traffic_snapshot",
        "uninstall",
        "update_binary",
    }
    assert expected <= set(vars(MtprotoZigPlugin))
