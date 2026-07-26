from unittest.mock import patch
from unittest.mock import MagicMock

from hydra.cli import main
from hydra.core.state import AppState


def test_reconcile_without_apply_is_plan_only(capsys):
    app = MagicMock()
    app.check.return_value = {
        "ok": True,
        "configuration": {"valid": True},
        "host": {"ok": True},
        "changes": {"valid": True, "reconciliation": []},
    }
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.cli.production_application",
        return_value=app,
    ):
        assert main(["reconcile"]) == 0
    app.check.assert_called_once()
    assert '"reconciliation": []' in capsys.readouterr().out


def test_reconcile_apply_requires_root():
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.cli._require_root", side_effect=PermissionError("root required"),
    ), patch(
        "hydra.cli.production_application",
        return_value=MagicMock(),
    ):
        assert main(["reconcile", "--apply"]) == 1
