from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra import cli
from hydra.core.state_models import AppState, User


def _application() -> MagicMock:
    app = MagicMock()
    app.check.return_value = {
        "ok": True,
        "configuration": {"valid": True, "schema_version": 4},
        "host": {"ok": True, "required_failures": []},
        "changes": {"valid": True, "plugins": []},
    }
    app.status.return_value = {"version": 4, "users": 0}
    return app


def test_canonical_status_and_check_commands_use_application_ports(capsys):
    state = AppState()
    app = _application()
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["check"]) == 0
        assert cli.main(["status"]) == 0

    app.check.assert_called_once_with(state)
    app.status.assert_called_once_with(state)
    assert len(capsys.readouterr().out.splitlines()) > 3


def test_validate_doctor_plan_and_reconcile_collapse_to_check(capsys):
    state = AppState()
    app = _application()
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["validate"]) == 0
        assert cli.main(["doctor"]) == 0
        assert cli.main(["plan"]) == 0
        assert cli.main(["reconcile"]) == 0
        assert cli.main(["config", "plan"]) == 0
        assert cli.main(["runtime", "doctor"]) == 0

    assert app.check.call_count == 6
    capsys.readouterr()


def test_apply_dry_run_is_the_same_read_only_check(capsys):
    state = AppState()
    app = _application()
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(
        cli,
        "_require_root",
        side_effect=AssertionError("dry-run must not require root"),
    ):
        assert cli.main(["apply", "--dry-run"]) == 0

    app.check.assert_called_once_with(state)
    app.apply_result.assert_not_called()
    capsys.readouterr()


def test_reconcile_apply_compatibility_alias_runs_full_apply(capsys):
    state = AppState()
    app = _application()
    app.apply_result.return_value = SimpleNamespace(
        ok=True,
        as_dict=lambda: {"ok": True, "value": True},
    )
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_require_root"):
        assert cli.main(["reconcile", "--apply"]) == 0

    app.apply_result.assert_called_once_with(state)
    app.check.assert_not_called()
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_backup_inspect_is_read_only_and_does_not_require_confirmation(capsys):
    state = AppState()
    app = _application()
    app.backups.inspect.return_value = {
        "valid": True,
        "archive": "/tmp/backup.tar.gz",
    }
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(
        cli,
        "_require_root",
        side_effect=AssertionError("inspection must be read-only"),
    ):
        assert cli.main(
            ["backup", "inspect", "/tmp/backup.tar.gz"],
        ) == 0

    app.backups.inspect.assert_called_once_with("/tmp/backup.tar.gz")
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_user_show_redacts_credentials(capsys):
    state = AppState(
        users=[
            User(
                email="alice",
                uuid="u1",
                credentials={"naive": {"password": "secret"}},
            ),
        ],
    )
    app = _application()
    app.users.get.return_value = state.users[0]
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["user", "show", "alice"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["user"]["email"] == "alice"
    assert payload["user"]["protocols"] == ["naive"]
    assert "credentials" not in payload["user"]
    assert "secret" not in json.dumps(payload)


def test_ensure_default_uses_transactional_user_boundary(capsys):
    state = AppState()
    app = _application()
    app.add_user.side_effect = lambda current, user: current.users.append(user)
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_require_root"), patch.object(
        cli,
        "save_state",
    ) as direct_save:
        assert cli.main(["user", "ensure-default"]) == 0

    app.add_user.assert_called_once()
    direct_save.assert_not_called()
    assert state.users[0].email == "default"
    assert json.loads(capsys.readouterr().out)["created"] is True


def test_plugin_list_uses_transport_neutral_inventory(capsys):
    state = AppState()
    app = _application()
    app.protocols.inventory.return_value = [
        {
            "name": "naive",
            "category": "transport",
            "capabilities": {"commands": ["set_transport"]},
            "status": {"installed": True, "enabled": False},
        },
    ]
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["plugin", "list", "--category", "transport"]) == 0

    app.protocols.inventory.assert_called_once_with(
        state,
        category="transport",
    )
    assert json.loads(capsys.readouterr().out)["plugins"][0]["name"] == "naive"


def test_plugin_lifecycle_reports_failed_boolean_as_exit_one(capsys):
    state = AppState()
    app = _application()
    app.protocols.lifecycle_result.return_value = SimpleNamespace(
        ok=False,
        as_dict=lambda: {
            "ok": False,
            "error": {
                "code": "operation_failed",
                "message": "enable failed for naive",
                "retryable": True,
            },
        },
    )
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_require_root"):
        assert cli.main(["plugin", "enable", "naive"]) == 1

    app.protocols.lifecycle_result.assert_called_once_with(
        state,
        "enable",
        "naive",
    )
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_root_requirement_uses_stable_host_error_code(capsys):
    app = _application()
    with patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(
        cli,
        "_require_root",
        side_effect=PermissionError("root required"),
    ):
        assert cli.main(["plugin", "enable", "naive"]) == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["error_details"]["code"] == "host_operation"
    app.protocols.lifecycle_result.assert_not_called()


def test_plugin_health_failure_is_machine_visible(capsys):
    state = AppState()
    app = _application()
    app.protocols.health.return_value = SimpleNamespace(
        healthy=False,
        as_dict=lambda: {
            "healthy": False,
            "detail": "service is not active",
            "severity": "error",
            "checks": {},
        },
    )
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["plugin", "health", "naive"]) == 1

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["health"]["severity"] == "error"


def test_plugin_command_parses_typed_repeatable_parameters(capsys):
    state = AppState()
    app = _application()
    app.plugin_command.return_value = True
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ), patch.object(cli, "_require_root"):
        assert cli.main(
            [
                "plugin",
                "command",
                "hysteria2",
                "set_port",
                "--param",
                "port=8443",
                "--param",
                'enabled=true',
                "--param",
                'label="edge"',
            ],
        ) == 0

    app.plugin_command.assert_called_once_with(
        state,
        "hysteria2",
        "set_port",
        port=8443,
        enabled=True,
        label="edge",
    )
    assert json.loads(capsys.readouterr().out)["changed"] is True


def test_plugin_query_can_receive_current_state_explicitly(capsys):
    state = AppState()
    app = _application()
    app.plugin_query.return_value = {"items": []}
    with patch.object(cli, "load_state", return_value=state), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(
            [
                "plugin",
                "query",
                "warp",
                "external_sources",
                "--with-state",
            ],
        ) == 0

    app.plugin_query.assert_called_once_with(
        "warp",
        "external_sources",
        state=state,
    )
    assert json.loads(capsys.readouterr().out)["result"] == {"items": []}


def test_parser_errors_are_json_and_do_not_build_application(capsys):
    with patch.object(cli, "production_application") as application:
        assert cli.main(["plugin", "status"]) == 2

    application.assert_not_called()
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error_details"]["code"] == "invalid_input"
    assert payload["error_details"]["usage"] == "hydra plugin status NAME"


def test_version_and_compact_output_do_not_load_state(capsys):
    with patch.object(cli, "load_state") as state_reader, patch.object(
        cli,
        "production_application",
    ) as application:
        assert cli.main(["--compact", "--version"]) == 0

    state_reader.assert_not_called()
    application.assert_not_called()
    output = capsys.readouterr().out
    assert "\n" not in output.strip()
    assert json.loads(output)["version"]


def test_global_output_flag_is_accepted_after_a_legacy_command(capsys):
    app = _application()
    with patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "production_application",
        return_value=app,
    ):
        assert cli.main(["status", "--compact"]) == 0

    output = capsys.readouterr().out
    assert "\n" not in output.strip()
    assert json.loads(output)["version"] == 4


def test_help_exposes_user_actions_not_internal_preflight_stages(capsys):
    assert cli.main(["--help"]) == 0

    help_text = capsys.readouterr().out
    for command in ("status", "check", "apply", "backup", "user", "plugin"):
        assert command in help_text
    for internal_name in (
        "validate",
        "doctor",
        "plan",
        "reconcile",
        "config",
        "runtime",
        "system",
    ):
        assert f"    {internal_name} " not in help_text
