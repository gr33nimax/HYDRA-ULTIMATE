from unittest.mock import patch
from unittest.mock import MagicMock

from hydra.cli import main
from hydra.core.state import AppState


def test_reconcile_without_apply_is_plan_only(capsys):
    app = MagicMock()
    app.protocols.reconciliation.return_value.plan.return_value = []
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.cli.production_application",
        return_value=app,
    ):
        assert main(["reconcile"]) == 0
    assert '"planned": []' in capsys.readouterr().out


def test_reconcile_apply_requires_root():
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.cli._require_root", side_effect=PermissionError("root required")
    ):
        assert main(["reconcile", "--apply"]) == 1
