from unittest.mock import patch

from hydra import cli
from hydra.core.state_models import AppState


def test_upgrade_migrate_state_uses_atomic_storage_boundary():
    application = object()
    result = {"from": 3, "to": 4, "changed": True}

    with patch.object(
        cli,
        "production_application",
        return_value=application,
    ), patch.object(cli, "load_state", return_value=AppState()), patch(
        "hydra.core.state.migrate_persisted_state",
        return_value=result,
    ) as migrate, patch.object(cli, "_require_root"), patch.object(
        cli,
        "_print",
    ) as output:
        assert cli.main(["upgrade", "migrate-state"]) == 0

    migrate.assert_called_once_with()
    output.assert_called_once_with(result)


def test_upgrade_migrate_state_requires_root():
    with patch.object(
        cli,
        "production_application",
        return_value=object(),
    ), patch.object(cli, "load_state", return_value=AppState()), patch.object(
        cli,
        "_require_root",
        side_effect=PermissionError("root required"),
    ), patch.object(cli, "_print") as output:
        assert cli.main(["upgrade", "migrate-state"]) == 1

    assert output.call_args.args[0]["ok"] is False
