"""Regression check for Python venv dependency detection."""
from pathlib import Path


BOOTSTRAP = (Path(__file__).parent.parent / "bootstrap.sh").read_text(encoding="utf-8")


def test_bootstrap_checks_ensurepip_instead_of_venv_help():
    assert "python3 -c 'import ensurepip'" in BOOTSTRAP
    assert "python3 -m venv --help" not in BOOTSTRAP
