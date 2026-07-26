from types import SimpleNamespace
from unittest.mock import patch

from hydra.core import doctor, upgrade
from hydra.core.doctor import run_doctor, run_host_preflight
from hydra.core.state import AppState
from hydra.core.upgrade import check_upgrade
from hydra.services.reconciliation import ReconcileAction


def test_doctor_reports_required_failures():
    with patch.object(doctor.HOST, "which", return_value=None), \
         patch("hydra.core.doctor.os.access", return_value=False):
        result = run_doctor(AppState())
    assert result["ok"] is False
    assert "state_directory" in result["required_failures"]


def test_host_preflight_does_not_require_state_directory_write_access():
    with patch.object(
        doctor.HOST,
        "which",
        side_effect=lambda command: f"/usr/bin/{command}",
    ), patch("hydra.core.doctor.os.access", return_value=False):
        result = run_host_preflight(AppState())

    assert result["ok"] is True
    assert all(
        check["name"] != "state_directory"
        for check in result["checks"]
    )


def test_doctor_exposes_runtime_reconciliation_plan():
    statuses = {"demo": {"drift": "stopped", "installed": True, "running": False}}
    protocols = SimpleNamespace(
        statuses=lambda state: statuses,
        reconciliation=lambda: SimpleNamespace(
            plan=lambda state: [
                ReconcileAction("demo", "stopped", "enable", "expected"),
            ],
        ),
    )
    result = run_doctor(AppState(), protocols)
    assert result["reconciliation"]["planned"][0]["plugin"] == "demo"
    assert result["reconciliation"]["planned"][0]["operation"] == "enable"


def test_upgrade_check_accepts_clean_supported_state(tmp_path):
    (tmp_path / ".git").mkdir()
    completed = type("Result", (), {"returncode": 0, "stdout": ""})()
    with patch.object(upgrade.HOST, "which", return_value="git"), \
         patch.object(upgrade.HOST, "run", return_value=completed):
        result = check_upgrade(AppState(), tmp_path)
    assert result["ready"] is True
    assert result["backup_required"] is True
