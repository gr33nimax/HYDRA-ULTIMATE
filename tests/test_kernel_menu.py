from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from hydra.core.state_models import AppState
from hydra.ui._menus.kernel import handle_kernel_choice


def test_kernel_menu_switches_hydracore_stable_to_debug() -> None:
    state = AppState()
    state.kernel.provider = "hydracore"
    state.kernel.channel = "stable"
    app = MagicMock()
    app.kernel.switch.return_value = SimpleNamespace(ok=True, message="switched")
    app.apply.return_value = True
    deps = MagicMock()

    handled = handle_kernel_choice(
        "8",
        state,
        app,
        deps,
        installed=True,
        update_available=False,
        confirm_action=lambda *_args, **_kwargs: True,
    )

    assert handled is True
    app.kernel.switch.assert_called_once_with(
        state,
        "hydracore",
        channel="debug",
        force=True,
    )
    app.apply.assert_called_once_with(state)


def test_kernel_menu_switches_hydracore_debug_back_to_stable() -> None:
    state = AppState()
    state.kernel.provider = "hydracore"
    state.kernel.channel = "debug"
    app = MagicMock()
    app.kernel.switch.return_value = SimpleNamespace(ok=True, message="switched")
    app.apply.return_value = True

    assert handle_kernel_choice(
        "8",
        state,
        app,
        MagicMock(),
        installed=True,
        update_available=False,
        confirm_action=lambda *_args, **_kwargs: True,
    ) is True

    app.kernel.switch.assert_called_once_with(
        state,
        "hydracore",
        channel="stable",
        force=True,
    )
