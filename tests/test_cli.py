from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra import cli
from hydra.core.state import AppState, PluginState, User


def test_build_plan_uses_copy_and_reports_changes():
    state = AppState(protocols={"mock": PluginState(enabled=True)})
    app = MagicMock()
    app.plan.return_value = {
        "valid": True,
        "reconciliation": [],
    }

    result = cli.build_plan(state, app)

    assert result["valid"] is True
    assert state.network.tproxy_enabled is False
    assert result["reconciliation"] == []
    app.plan.assert_called_once_with(state)


def test_validate_command_prints_json(capsys):
    with patch.object(cli, "load_state", return_value=AppState()):
        assert cli.main(["validate"]) == 0
    assert '"valid": true' in capsys.readouterr().out


def test_user_list_does_not_require_root(capsys):
    state = AppState(users=[User(email="u@example.com", uuid="u1", credentials={"naive": {"password": "secret"}})])
    with patch.object(cli, "load_state", return_value=state):
        assert cli.main(["user", "list"]) == 0
    output = capsys.readouterr().out
    assert "u@example.com" in output
    assert "secret" not in output
    assert '"protocols": [\n        "naive"' in output


def test_ensure_default_user_only_creates_on_empty_state(capsys):
    state = AppState()
    with patch.object(cli, "load_state", return_value=state), \
         patch.object(cli, "save_state") as save, \
         patch.object(cli, "_require_root"):
        assert cli.main(["user", "ensure-default"]) == 0
    assert len(state.users) == 1
    assert state.users[0].email == "default"
    save.assert_called_once_with(state)
    assert '"created": true' in capsys.readouterr().out


def test_uninstall_requires_confirmation(capsys):
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"):
        assert cli.main(["uninstall"]) == 1
    assert "uninstall requires --yes" in capsys.readouterr().out


def test_uninstall_dispatches_through_application_boundary(capsys):
    state = AppState()
    app = MagicMock()
    app.uninstall.return_value = {
        "ok": True,
        "dry_run": True,
        "plugins": [],
        "services": [],
        "paths": [],
        "keep_data": True,
    }
    with patch.object(cli, "load_state", return_value=state), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main(
            ["uninstall", "--yes", "--dry-run", "--keep-data"],
        ) == 0

    app.uninstall.assert_called_once_with(
        state,
        confirmed=True,
        dry_run=True,
        keep_data=True,
    )
    assert '"dry_run": true' in capsys.readouterr().out


def test_backup_command_dispatches_to_backup_service(capsys):
    result = {"ok": True, "archive": "/tmp/hydra.tar.gz", "files": 1, "bytes": 42}
    app = MagicMock()
    app.backups.create.return_value = result
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main(["backup", "--output", "/tmp/hydra.tar.gz"]) == 0
    app.backups.create.assert_called_once_with("/tmp/hydra.tar.gz")
    assert '"archive": "/tmp/hydra.tar.gz"' in capsys.readouterr().out


def test_restore_requires_confirmation(capsys):
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"):
        assert cli.main(["restore", "/tmp/backup.tar.gz"]) == 1
    assert "restore requires --yes" in capsys.readouterr().out


def test_restore_dry_run_dispatches(capsys):
    result = {"valid": True, "dry_run": True, "changes": 1}
    app = MagicMock()
    app.backups.restore.return_value = result
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main(["restore", "/tmp/backup.tar.gz", "--dry-run"]) == 0
    app.backups.restore.assert_called_once_with(
        "/tmp/backup.tar.gz",
        dry_run=True,
    )
    assert '"dry_run": true' in capsys.readouterr().out


def test_antidpi_selftest_dispatches(capsys):
    result = {"ok": True, "archive": "/tmp/antidpi.tar.gz"}
    app = MagicMock()
    app.plugin_action.return_value = result
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main(["antidpi", "selftest", "--output", "/tmp/antidpi.tar.gz", "--wait", "0", "--full"]) == 0
    app.plugin_action.assert_called_once_with(
        "antidpi",
        "run_selftest",
        state=AppState(),
        output="/tmp/antidpi.tar.gz",
        wait_seconds=0.0,
        full=True,
        protocols=app.protocols,
    )
    assert '"archive": "/tmp/antidpi.tar.gz"' in capsys.readouterr().out


def test_antidpi_capture_dispatches(capsys):
    result = {"ok": True, "archive": "/tmp/capture.tar.gz"}
    app = MagicMock()
    app.plugin_action.return_value = result
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main([
            "antidpi", "capture", "--output", "/tmp/capture.tar.gz", "--seconds", "30",
        ]) == 0
    app.plugin_action.assert_called_once_with(
        "antidpi",
        "capture_external_tests",
        state=AppState(),
        output="/tmp/capture.tar.gz",
        seconds=30.0,
    )


def test_antidpi_sync_reinstalls_and_reports_health(capsys):
    health = type("Health", (), {
        "healthy": True,
        "as_dict": lambda self: {"healthy": True, "checks": {"udp": True}},
    })()
    protocols = MagicMock()
    protocols.install.return_value = True
    protocols.health.return_value = health
    app = MagicMock(protocols=protocols)
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch.object(cli, "production_application", return_value=app):
        assert cli.main(["antidpi", "sync"]) == 0
    protocols.install.assert_called_once_with(AppState(), "antidpi")
    protocols.health.assert_called_once_with(AppState(), "antidpi")
    output = capsys.readouterr().out
    assert '"ok": true' in output
    assert '"udp": true' in output
