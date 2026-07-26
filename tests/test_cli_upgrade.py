from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra import cli
from hydra.core.state_models import AppState


def test_upgrade_migrate_state_uses_atomic_storage_boundary():
    result = {"from": 3, "to": 4, "changed": True}
    system = MagicMock()
    system.migrate_state.return_value = result
    application = SimpleNamespace(system=system)

    with patch.object(
        cli,
        "production_application",
        return_value=application,
    ), patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "_require_root",
    ), patch.object(
        cli,
        "_print",
    ) as output:
        assert cli.main(["upgrade", "migrate-state"]) == 0

    system.migrate_state.assert_called_once_with()
    output.assert_called_once_with(result)


def test_upgrade_migrate_state_requires_root():
    system = MagicMock()
    with patch.object(
        cli,
        "production_application",
        return_value=SimpleNamespace(system=system),
    ), patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "_require_root",
        side_effect=PermissionError("root required"),
    ), patch.object(cli, "_print") as output:
        assert cli.main(["upgrade", "migrate-state"]) == 1

    assert output.call_args.args[0]["ok"] is False
    system.migrate_state.assert_not_called()
