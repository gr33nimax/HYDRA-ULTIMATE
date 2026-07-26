"""Architecture guards for the split Sing-Box subsystem."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
CORE = ROOT / "hydra" / "core"


def test_singbox_facade_stays_below_the_god_module_threshold() -> None:
    facade = CORE / "singbox.py"
    assert len(facade.read_text(encoding="utf-8").splitlines()) < 500
    assert (CORE / "singbox_config.py").is_file()
    assert (CORE / "singbox_upgrade.py").is_file()


def test_singbox_configuration_assembly_is_host_independent() -> None:
    path = CORE / "singbox_config.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden_imports = {
        "os",
        "pathlib",
        "shutil",
        "subprocess",
        "hydra.core.host",
    }
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            modules = {node.module or ""}
        else:
            modules = set()
        for module in modules & forbidden_imports:
            violations.append(f"{node.lineno}: import {module}")
        if isinstance(node, ast.Name) and node.id == "HOST":
            violations.append(f"{node.lineno}: HOST")
        if (
            isinstance(node, ast.Attribute)
            and node.attr in {
                "mkdir",
                "read_bytes",
                "read_text",
                "unlink",
                "write_bytes",
                "write_text",
            }
        ):
            violations.append(f"{node.lineno}: .{node.attr}")

    assert violations == []


def test_singbox_public_upgrade_is_only_dependency_wiring() -> None:
    path = CORE / "singbox.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "update_kernel"
    )

    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "upgrade_kernel"
    ]
    assert len(calls) == 1
    assert function.end_lineno - function.lineno < 25
