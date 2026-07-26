"""Architecture regression guards for the modular AntiDPI package."""
from __future__ import annotations

import ast
from pathlib import Path

from hydra.plugins.antidpi.plugin import AntiDPIPlugin

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "hydra" / "plugins" / "antidpi"


def _imports(tree: ast.AST) -> set[str]:
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_antidpi_modules_remain_bounded():
    """Prevent the extracted responsibilities from collapsing into new gods."""
    violations = []
    for path in sorted(PACKAGE.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        line_count = len(source.splitlines())
        if line_count > 500:
            violations.append(f"{path.name}: {line_count} lines")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            function_lines = (node.end_lineno or node.lineno) - node.lineno + 1
            if function_lines > 150:
                violations.append(
                    f"{path.name}:{node.lineno} {node.name} "
                    f"is {function_lines} lines",
                )
    assert violations == [], "; ".join(violations)


def test_antidpi_facades_delegate_to_focused_modules():
    expected = {
        "detection.py",
        "detector_service.py",
        "firewall.py",
        "firewall_rules.py",
        "lifecycle.py",
        "management.py",
        "model.py",
        "normalization.py",
        "runtime.py",
        "selftest_capture.py",
        "selftest_probes.py",
        "selftest_report.py",
        "selftest_targets.py",
        "state_store.py",
    }
    assert expected <= {path.name for path in PACKAGE.glob("*.py")}
    assert len(
        (PACKAGE / "plugin.py").read_text(encoding="utf-8").splitlines(),
    ) < 350
    assert len(
        (PACKAGE / "selftest.py").read_text(encoding="utf-8").splitlines(),
    ) <= 500


def test_antidpi_pure_model_has_no_host_or_persistence_dependencies():
    forbidden = {
        "hydra.core.host",
        "hydra.core.state",
        "hydra.plugins.registry",
        "hydra.plugins.invoker",
        "os",
        "pathlib",
        "subprocess",
    }
    violations = []
    for name in ("detection.py", "model.py", "normalization.py"):
        path = PACKAGE / name
        imported = _imports(
            ast.parse(path.read_text(encoding="utf-8")),
        )
        for module in sorted(imported & forbidden):
            violations.append(f"{name}: {module}")
    assert violations == []


def test_antidpi_selftest_uses_injected_application_boundaries():
    violations = []
    forbidden_imports = {
        "hydra.plugins.invoker",
        "hydra.plugins.registry",
        "hydra.plugins.antidpi.plugin",
    }
    for path in sorted(PACKAGE.glob("selftest*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for module in sorted(_imports(tree) & forbidden_imports):
            violations.append(f"{path.name}: import {module}")
        for marker in (
            "DEFAULT_INVOKER",
            "get_registered_plugin",
            "._load_state(",
        ):
            if marker in source:
                violations.append(f"{path.name}: {marker}")
    assert violations == []


def test_antidpi_has_one_canonical_remote_ip_parser():
    definitions = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        definitions.extend(
            (path.name, node.name)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name in {"remote_ip", "_remote_ip"}
        )
    assert definitions == [("adapters.py", "remote_ip")]


def test_antidpi_management_capabilities_are_declared():
    capabilities = AntiDPIPlugin.meta.capabilities
    assert capabilities.commands == (
        "add_whitelist",
        "remove_whitelist",
        "unban_address",
    )
    assert capabilities.queries == (
        "management_snapshot",
        "recent_logs",
    )
    assert capabilities.actions == (
        "capture_external_tests",
        "manual_ban",
        "run_selftest",
        "unban",
    )
