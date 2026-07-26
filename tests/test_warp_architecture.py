"""Architecture and compatibility boundaries for the modular WARP plugin."""

from __future__ import annotations

import ast
from pathlib import Path

import hydra.plugins.warp.plugin as facade


ROOT = Path(__file__).parents[1]
WARP_ROOT = ROOT / "hydra" / "plugins" / "warp"


def test_warp_facade_preserves_public_symbols():
    expected = {
        "DEFAULT_WARP_DOMAINS",
        "EXTERNAL_LISTS",
        "RUSSIA_TLD_SUFFIXES",
        "WARP_EXTERNAL_CACHE",
        "WARP_INTERFACE",
        "WARP_PROFILES_DIR",
        "WGCF_ACCOUNT",
        "WGCF_BIN",
        "WGCF_PROFILE",
        "WarpPlugin",
    }
    assert not (expected - vars(facade).keys())


def test_warp_implementation_stays_decomposed():
    limits = {
        "plugin.py": 180,
        "configuration.py": 350,
        "constants.py": 350,
        "observation.py": 350,
        "parsing.py": 350,
        "rules.py": 350,
        "runtime.py": 350,
    }
    violations = []
    for name, limit in limits.items():
        path = WARP_ROOT / name
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > limit:
            violations.append(f"{name}: {len(lines)} > {limit}")
        tree = ast.parse("\n".join(lines))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = node.end_lineno - node.lineno + 1
                if length > 100:
                    violations.append(f"{name}:{node.name}: {length} > 100")
    assert violations == []


def test_warp_plugin_layer_has_no_outer_layer_dependencies():
    forbidden = ("hydra.services", "hydra.ui", "hydra.entrypoints")
    violations = []
    for path in WARP_ROOT.glob("*.py"):
        if path.name == "manager.py":  # Deprecated UI compatibility alias.
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
            for imported in imports:
                if imported == "hydra.plugins.registry" or imported.startswith(
                    forbidden
                ):
                    violations.append(f"{path.name}:{node.lineno} {imported}")
    assert violations == []
