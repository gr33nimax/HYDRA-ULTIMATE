from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.core.errors import ApplicationError, ErrorCode, ServiceResult
from hydra.core.state import AppState, PluginState
from hydra.services.logs import LogReadResult
from hydra.ui.plugin_managers._warp_menu import (
    _recreate_or_install_profile,
    _status_lines,
)


def _failed_install_application(detail: str):
    result = ServiceResult(
        False,
        error=ApplicationError(
            ErrorCode.PLUGIN,
            detail,
        ),
    )
    return SimpleNamespace(
        protocols=SimpleNamespace(
            lifecycle_result=MagicMock(return_value=result),
        ),
        logs=SimpleNamespace(
            read=MagicMock(
                return_value=LogReadResult(
                    lines=(
                        "wgcf register failed with code 1",
                        "Stderr: Cloudflare registration timed out",
                    ),
                ),
            ),
        ),
        apply=MagicMock(),
    )


def test_local_wgcf_install_failure_shows_service_and_runtime_details():
    state = AppState(protocols={"warp": PluginState()})
    app = _failed_install_application("install failed for warp")

    with (
        patch("hydra.ui.plugin_managers._warp_menu.info"),
        patch("hydra.ui.plugin_managers._warp_menu.error") as show_error,
        patch("hydra.ui.plugin_managers._warp_menu.prompt"),
    ):
        _recreate_or_install_profile(
            state,
            app,
            state.protocols["warp"],
            default_exists=False,
        )

    message = show_error.call_args.args[0]
    assert "install failed for warp" in message
    assert "wgcf register failed with code 1" in message
    assert "Cloudflare registration timed out" in message
    app.protocols.lifecycle_result.assert_called_once_with(
        state,
        "install",
        "warp",
    )


def test_recreate_failure_shows_wgcf_runtime_log():
    state = AppState(protocols={"warp": PluginState()})
    app = SimpleNamespace(
        plugin_action=MagicMock(
            side_effect=[
                (b"profile", b"account"),
                False,
            ],
        ),
        logs=SimpleNamespace(
            read=MagicMock(
                return_value=LogReadResult(
                    lines=("wgcf generate failed with code 1",),
                ),
            ),
        ),
        apply=MagicMock(),
    )

    with (
        patch("hydra.ui.plugin_managers._warp_menu.warn"),
        patch("hydra.ui.plugin_managers._warp_menu.confirm", return_value=True),
        patch("hydra.ui.plugin_managers._warp_menu.error") as show_error,
        patch("hydra.ui.plugin_managers._warp_menu.prompt"),
    ):
        _recreate_or_install_profile(
            state,
            app,
            state.protocols["warp"],
            default_exists=True,
        )

    assert "wgcf generate failed with code 1" in show_error.call_args.args[0]


def test_disabled_status_marks_routes_inactive_and_missing_target_invalid():
    lines = _status_lines(
        SimpleNamespace(installed=True, enabled=False, running=False),
        ["Finland"],
        ["direct", "warp_Finland"],
        {"ext:google_ai": "warp"},
        {"google_ai": {"name": "GoogleAI"}},
    )
    rendered = "\n".join(lines)

    assert "маршруты WARP сейчас не применяются" in rendered
    assert "warp (недоступен)" in rendered
