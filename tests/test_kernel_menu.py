from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from hydra.core.state_models import AppState
from hydra.ui._menus import core
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


def test_core_menu_shows_the_selected_channel_and_the_candidate_version() -> None:
    state = AppState()
    state.kernel.channel = "debug"
    state.install["singbox_latest_version"] = "hydracore-sbe-1.14.0-rc-1"
    captured = {}

    app = MagicMock()
    app.admin.load_state.return_value = state
    app.kernel.status.return_value = SimpleNamespace(
        runtime=SimpleNamespace(
            installed=True,
            running=True,
            version="1.13.16-extended-hydracore.9",
            provider="hydracore",
        ),
    )

    core.run_core_menu(
        state,
        app,
        core.CoreMenuDependencies(
            clear=lambda: None,
            panel=lambda title, lines, **kwargs: captured.update(title=title, lines=lines),
            kv=lambda label, value: f"{label} {value}",
            status_marker=lambda running: "✓" if running else "✗",
            menu=lambda *_: "0",
            info=lambda *_: None,
            success=lambda *_: None,
            warn=lambda *_: None,
            prompt=lambda *_: "",
            error=lambda *_: None,
            apply_error_text=lambda *_: "",
            apply_network_tuning=lambda *_: None,
            rollback_network_tuning=lambda *_: None,
            yellow="",
            dim="",
            reset="",
        ),
    )

    assert captured["title"] == "Sing-Box"
    assert "Канал: debug" in captured["lines"]
    assert "Кандидат: hydracore-sbe-1.14.0-rc-1" in captured["lines"]


def test_core_menu_shows_no_candidate_before_the_first_update_check() -> None:
    state = AppState()
    captured = {}

    app = MagicMock()
    app.admin.load_state.return_value = state
    app.kernel.status.return_value = SimpleNamespace(
        runtime=SimpleNamespace(
            installed=False,
            running=False,
            version="",
            provider="unknown",
        ),
    )

    core.run_core_menu(
        state,
        app,
        core.CoreMenuDependencies(
            clear=lambda: None,
            panel=lambda title, lines, **kwargs: captured.update(title=title, lines=lines),
            kv=lambda label, value: f"{label} {value}",
            status_marker=lambda running: "✓" if running else "✗",
            menu=lambda *_: "0",
            info=lambda *_: None,
            success=lambda *_: None,
            warn=lambda *_: None,
            prompt=lambda *_: "",
            error=lambda *_: None,
            apply_error_text=lambda *_: "",
            apply_network_tuning=lambda *_: None,
            rollback_network_tuning=lambda *_: None,
            yellow="",
            dim="",
            reset="",
        ),
    )

    assert "Канал: stable" in captured["lines"]
    assert "Кандидат: —" in captured["lines"]
