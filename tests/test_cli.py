from __future__ import annotations

from unittest.mock import patch

from hydra import cli
from hydra.core.state import AppState, PluginState, User


def test_build_plan_uses_copy_and_reports_changes():
    state = AppState(protocols={"mock": PluginState(enabled=True)})
    with patch("hydra.plugins.registry.collect_fragments", return_value={}), \
         patch("hydra.core.singbox.generate_config", return_value={"inbounds": [], "outbounds": [], "route": {"rules": []}}), \
         patch("hydra.core.singbox._preflight_conflicts", return_value=[]), \
         patch("hydra.plugins.registry.status_all", return_value={}):
        result = cli.build_plan(state)
    assert result["valid"] is True
    assert state.network.tproxy_enabled is False
    assert result["reconciliation"] == []


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


def test_backup_command_dispatches_to_backup_service(capsys):
    result = {"ok": True, "archive": "/tmp/hydra.tar.gz", "files": 1, "bytes": 42}
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch("hydra.core.backup.create_backup", return_value=result) as create:
        assert cli.main(["backup", "--output", "/tmp/hydra.tar.gz"]) == 0
    create.assert_called_once_with("/tmp/hydra.tar.gz")
    assert '"archive": "/tmp/hydra.tar.gz"' in capsys.readouterr().out


def test_restore_requires_confirmation(capsys):
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"):
        assert cli.main(["restore", "/tmp/backup.tar.gz"]) == 1
    assert "restore requires --yes" in capsys.readouterr().out


def test_restore_dry_run_dispatches(capsys):
    result = {"valid": True, "dry_run": True, "changes": 1}
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch("hydra.core.backup.restore_backup", return_value=result) as restore:
        assert cli.main(["restore", "/tmp/backup.tar.gz", "--dry-run"]) == 0
    restore.assert_called_once_with("/tmp/backup.tar.gz", dry_run=True)
    assert '"dry_run": true' in capsys.readouterr().out


def test_antidpi_selftest_dispatches(capsys):
    result = {"ok": True, "archive": "/tmp/antidpi.tar.gz"}
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch("hydra.plugins.antidpi.selftest.run_selftest", return_value=result) as run:
        assert cli.main(["antidpi", "selftest", "--output", "/tmp/antidpi.tar.gz", "--wait", "0", "--full"]) == 0
    run.assert_called_once_with(AppState(), "/tmp/antidpi.tar.gz", 0.0, full=True)
    assert '"archive": "/tmp/antidpi.tar.gz"' in capsys.readouterr().out


def test_antidpi_capture_dispatches(capsys):
    result = {"ok": True, "archive": "/tmp/capture.tar.gz"}
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch("hydra.plugins.antidpi.selftest.capture_external_tests", return_value=result) as capture:
        assert cli.main([
            "antidpi", "capture", "--output", "/tmp/capture.tar.gz", "--seconds", "30",
        ]) == 0
    capture.assert_called_once_with(AppState(), "/tmp/capture.tar.gz", 30.0)


def test_antidpi_sync_reinstalls_and_reports_health(capsys):
    health = type("Health", (), {
        "healthy": True,
        "as_dict": lambda self: {"healthy": True, "checks": {"udp": True}},
    })()
    plugin = type("Plugin", (), {
        "last_error": "",
        "install": lambda self: True,
        "healthcheck": lambda self: health,
    })()
    with patch.object(cli, "load_state", return_value=AppState()), \
         patch.object(cli, "_require_root"), \
         patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin", return_value=plugin):
        assert cli.main(["antidpi", "sync"]) == 0
    output = capsys.readouterr().out
    assert '"ok": true' in output
    assert '"udp": true' in output
