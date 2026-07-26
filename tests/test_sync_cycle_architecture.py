"""Architectural constraints for the background synchronization cycle."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_sync_entrypoint_is_a_thin_process_adapter() -> None:
    path = ROOT / "hydra" / "services" / "sync_agent.py"
    assert len(path.read_text(encoding="utf-8").splitlines()) < 110


def test_sync_cycle_is_split_into_bounded_phases() -> None:
    path = ROOT / "hydra" / "services" / "sync_cycle.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    assert max(
        node.end_lineno - node.lineno + 1
        for node in functions
    ) <= 90
