from __future__ import annotations

import runpy
import sys
from contextlib import contextmanager
from types import ModuleType
from unittest.mock import Mock, patch

import pytest


def _entrypoint_module(name: str, result=None) -> tuple[ModuleType, Mock]:
    module = ModuleType(name)
    main = Mock(return_value=result)
    module.main = main
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

    with patch.dict(sys.modules, {name: entrypoint}), _without_loaded_module(
        "hydra.services.subscriptions.generator",
    ):
        runpy.run_module(
            "hydra.services.subscriptions.generator",
            run_name="__main__",
        )

    main.assert_called_once_with()


def test_legacy_sync_module_preserves_entrypoint_exit_code():
    name = "hydra.entrypoints.sync_agent"
    entrypoint, main = _entrypoint_module(name, result=7)

    with patch.dict(sys.modules, {name: entrypoint}), _without_loaded_module(
        "hydra.services.sync_agent",
    ):
        with pytest.raises(SystemExit, match="7"):
            runpy.run_module("hydra.services.sync_agent", run_name="__main__")

    main.assert_called_once_with()
