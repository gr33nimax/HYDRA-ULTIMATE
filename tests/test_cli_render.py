from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from hydra import cli
from hydra.cli_render import COMMAND_TITLES, render_human
from hydra.core.state_models import AppState


PUBLIC_COMMAND_IDS = {
    "status",
    "check",
    "apply",
    "backup.create",
    "backup.inspect",
    "backup.restore",
    "upgrade.check",
    "upgrade.migrate-state",
    "kernel.status",
    "kernel.switch",
    "user.list",
    "user.show",
    "user.add",
    "user.ensure-default",
    "user.rename",
    "user.set-device-limit",
    "user.rotate-hydrabox-key",
    "user.block",
    "user.unblock",
    "user.remove",
    "plugin.list",
    "plugin.show",
    "plugin.status",
    "plugin.health",
    "plugin.install",
    "plugin.reinstall",
    "plugin.enable",
    "plugin.disable",
    "plugin.uninstall",
    "plugin.command",
    "plugin.query",
    "plugin.action",
    "uninstall",
    "antidpi.selftest",
    "antidpi.capture",
    "antidpi.sync",
    "version",
}


def _parser_command_ids(parser: argparse.ArgumentParser) -> set[str]:
    command_ids: set[str] = set()
    visited: set[int] = set()

    def visit(current: argparse.ArgumentParser) -> None:
        if id(current) in visited:
            return
        visited.add(id(current))
        command_id = current.get_default("command_id")
        if command_id:
            command_ids.add(command_id)
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    visit(child)

    visit(parser)
    return command_ids


def test_every_public_command_has_an_explicit_human_title():
    assert set(COMMAND_TITLES) == PUBLIC_COMMAND_IDS
    assert _parser_command_ids(cli.parser()) | {"version"} == PUBLIC_COMMAND_IDS

    for command_id in PUBLIC_COMMAND_IDS:
        output = render_human(command_id, {"ok": True}, color=False)
        assert COMMAND_TITLES[command_id] in output
        assert not output.lstrip().startswith("{")


def test_status_renderer_is_compact_and_operator_focused():
    output = render_human(
        "status",
        {
            "version": 4,
            "users": 2,
            "network": {"domain": "vpn.example.com"},
            "plugins": {
                "naive": {
                    "enabled": True,
                    "installed": True,
                    "running": False,
                    "drift": "stopped",
                },
            },
            "runtime": {"naive": {"drift": "stopped"}},
            "tls_mux": {"ok": True, "required": True},
        },
        color=False,
    )

    assert "HYDRA status" in output
    assert "State format" in output
    assert "2 users" in output
    assert "vpn.example.com" in output
    assert "naive" in output
    assert "stopped" in output
    assert '"network"' not in output


def test_check_renderer_groups_failures_and_pending_changes():
    output = render_human(
        "check",
        {
            "ok": False,
            "configuration": {"valid": True, "schema_version": 4},
            "host": {
                "ok": False,
                "required_failures": ["systemctl"],
                "warnings": ["nft"],
                "checks": [
                    {
                        "name": "systemctl",
                        "ok": False,
                        "required": True,
                        "detail": "not found",
                    },
                ],
            },
            "changes": {
                "valid": True,
                "plugins": ["naive"],
                "conflicts": [],
                "reconciliation": [
                    {
                        "plugin": "naive",
                        "operation": "enable",
                        "reason": "stopped",
                    },
                ],
                "tls_mux": {"ok": True, "required": True},
                "changes": {"inbounds": 1, "outbounds": 2},
            },
        },
        color=False,
    )

    assert "Preflight failed" in output
    assert "Host checks" in output
    assert "systemctl" in output
    assert "Pending changes" in output
    assert "enable" in output
    assert "sudo hydra apply" not in output


def test_user_and_plugin_lists_render_as_tables():
    users = render_human(
        "user.list",
        {
            "users": [
                {
                    "email": "alice@example.com",
                    "blocked": False,
                    "protocols": ["naive", "warp"],
                    "devices_registered": 2,
                    "device_limit": 3,
                },
            ],
        },
        color=False,
    )
    plugins = render_human(
        "plugin.list",
        {
            "plugins": [
                {
                    "name": "naive",
                    "category": "transport",
                    "status": {
                        "enabled": True,
                        "installed": True,
                        "running": True,
                    },
                },
            ],
        },
        color=False,
    )

    assert "alice@example.com" in users
    assert "2/3" in users
    assert "naive, warp" in users
    assert "Name" in plugins
    assert "transport" in plugins
    assert "running" in plugins


def test_human_error_contains_actionable_code_and_usage():
    output = render_human(
        "error",
        {
            "ok": False,
            "error": "root required",
            "error_details": {
                "code": "host_operation",
                "message": "root required",
                "retryable": False,
                "usage": "hydra plugin enable NAME",
            },
        },
        color=False,
    )

    assert "Command failed" in output
    assert "root required" in output
    assert "host_operation" in output
    assert "hydra plugin enable NAME" in output
    assert "error_details" not in output


def test_tty_uses_human_output_while_json_flag_is_machine_stable(capsys):
    app = MagicMock()
    app.status.return_value = {"version": 4, "users": 0}
    with patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_stdout_is_tty", return_value=True):
        assert cli.main(["status"]) == 0
        human = capsys.readouterr().out
        assert "HYDRA status" in human

        assert cli.main(["status", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["version"] == 4


def test_tty_parser_error_is_human_and_actionable(capsys):
    with patch.object(cli, "_stdout_is_tty", return_value=True):
        assert cli.main(["plugin", "status"]) == 2

    output = capsys.readouterr().out
    assert "Command failed" in output
    assert "hydra plugin status NAME" in output
    assert not output.lstrip().startswith("{")


@pytest.mark.parametrize("flag", ["--json", "--compact"])
def test_explicit_machine_formats_work_on_a_tty(flag, capsys):
    app = MagicMock()
    app.status.return_value = {"version": 4, "users": 0}
    with patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_stdout_is_tty", return_value=True):
        assert cli.main(["status", flag]) == 0

    assert json.loads(capsys.readouterr().out)["version"] == 4
