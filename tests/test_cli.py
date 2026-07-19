from __future__ import annotations

from unittest.mock import patch

from hydra import cli
from hydra.core.state import AppState, PluginState, User


def test_build_plan_uses_copy_and_reports_changes():
    state = AppState(protocols={"mock": PluginState(enabled=True)})
    with patch("hydra.plugins.registry.collect_fragments", return_value={}), \
         patch("hydra.core.singbox.generate_config", return_value={"inbounds": [], "outbounds": [], "route": {"rules": []}}), \
         patch("hydra.core.singbox._preflight_conflicts", return_value=[]):
        result = cli.build_plan(state)
    assert result["valid"] is True
    assert state.network.tproxy_enabled is False


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
