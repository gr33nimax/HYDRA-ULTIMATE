from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import subprocess

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
    protocols: Any = SimpleNamespace(
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


def test_upgrade_check_names_what_makes_the_checkout_dirty(tmp_path):
    """An operator cannot clean what the refusal does not name."""
    (tmp_path / ".git").mkdir()
    completed = type(
        "Result",
        (),
        {"returncode": 0, "stdout": "?? .hydra-build.json\n M hydra/main.py\n"},
    )()
    with patch.object(upgrade.HOST, "which", return_value="git"), \
         patch.object(upgrade.HOST, "run", return_value=completed):
        result = check_upgrade(AppState(), tmp_path)

    assert result["ready"] is False
    assert "git_worktree" in result["failures"]
    detail = next(
        item["detail"] for item in result["checks"] if item["name"] == "git_worktree"
    )
    assert ".hydra-build.json" in detail
    assert "hydra/main.py" in detail


def test_installed_build_stamp_is_ignored_by_git():
    """The updater stamps .hydra-build.json into the tree; git must not call it dirt.

    The updater writes the stamp before the readiness preflight runs, so a missing
    ignore rule makes every upgrade refuse itself with "local changes detected".
    """
    repository_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        ["git", "-C", str(repository_root), "check-ignore", "-q", ".hydra-build.json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in (0, 1):
        return  # not a git checkout here; the rule is still asserted by the file itself
    assert completed.returncode == 0, ".hydra-build.json must be ignored by git"
