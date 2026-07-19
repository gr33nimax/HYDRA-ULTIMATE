from unittest.mock import patch

from hydra.cli import main
from hydra.core.state import AppState


def test_reconcile_without_apply_is_plan_only(capsys):
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.plugins.registry.status_all", return_value={}
    ):
        assert main(["reconcile"]) == 0
    assert '"planned": []' in capsys.readouterr().out


def test_reconcile_apply_requires_root():
    with patch("hydra.cli.load_state", return_value=AppState()), patch(
        "hydra.cli._require_root", side_effect=PermissionError("root required")
    ):
        assert main(["reconcile", "--apply"]) == 1
