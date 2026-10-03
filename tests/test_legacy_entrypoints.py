from __future__ import annotations

import runpy
import sys
from pathlib import Path
from contextlib import contextmanager
from types import ModuleType
from unittest.mock import Mock, patch

import pytest


def _entrypoint_module(name: str, result=None) -> tuple[ModuleType, Mock]:
    module = ModuleType(name)
    main = Mock(return_value=result)
    setattr(module, "main", main)
    return module, main


@contextmanager
def _without_loaded_module(name: str):
    previous = sys.modules.pop(name, None)
    try:
        yield
    finally:
        if previous is not None:
            sys.modules[name] = previous


def test_legacy_subscription_module_delegates_when_executed():
    name = "hydra.entrypoints.subscription_server"
    entrypoint, main = _entrypoint_module(name)

    with (
        patch.dict(sys.modules, {name: entrypoint}),
        _without_loaded_module(
            "hydra.services.subscriptions.generator",
        ),
    ):
        runpy.run_module(
            "hydra.services.subscriptions.generator",
            run_name="__main__",
        )

    main.assert_called_once_with()


def test_retired_node_product_has_no_legacy_entrypoints_or_contracts():
    root = Path(__file__).parents[1]
    removed = (
        "hydra/entrypoints/node_control.py",
        "hydra/entrypoints/node_provision.py",
        "hydra/entrypoints/node_cookies.py",
        "hydra/entrypoints/ssh_askpass.py",
        "hydra/core/node_identity.py",
        "hydra/core/state_nodes.py",
        "hydra/contracts/node_snapshot.py",
        "hydra/contracts/node_export.py",
        "hydra/contracts/node_traffic.py",
        "hydra/contracts/node_validation.py",
        "hydra/services/node_traffic_accounting.py",
        "hydra/services/nodes/bootstrap.py",
        "hydra/services/nodes/manager.py",
        "hydra/ui/_menus/nodes.py",
        "hydra/ui/_menus/node_details.py",
        "hydra/ui/_menus/node_cookies.py",
        "hydra/ui/_menus/node_removal.py",
    )
    assert all(not (root / path).exists() for path in removed)
    managed_ssh = (root / "hydra/services/managed_nodes/ssh.py").read_text(encoding="utf-8")
    assert "hydra-node-control.service" not in managed_ssh


def test_legacy_sync_module_preserves_entrypoint_exit_code():
    name = "hydra.entrypoints.sync_agent"
    entrypoint, main = _entrypoint_module(name, result=7)

    with (
        patch.dict(sys.modules, {name: entrypoint}),
        _without_loaded_module(
            "hydra.services.sync_agent",
        ),
    ):
        with pytest.raises(SystemExit, match="7"):
            runpy.run_module("hydra.services.sync_agent", run_name="__main__")

    main.assert_called_once_with()
