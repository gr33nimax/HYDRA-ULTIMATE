"""Repository-wide backstop against new god modules and giant functions."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
PRODUCTION = ROOT / "hydra"
MAX_MODULE_LINES = 500
MAX_FUNCTION_LINES = 160


def test_production_modules_and_functions_stay_reviewable() -> None:
    oversized_modules: list[str] = []
    oversized_functions: list[str] = []

    for path in sorted(PRODUCTION.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        line_count = len(source.splitlines())
        if line_count > MAX_MODULE_LINES:
            oversized_modules.append(f"{relative}={line_count}")

        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            end = node.end_lineno or node.lineno
            size = end - node.lineno + 1
            if size > MAX_FUNCTION_LINES:
                oversized_functions.append(
                    f"{relative}:{node.lineno} {node.name}={size}"
                )

    assert oversized_modules == []
    assert oversized_functions == []
