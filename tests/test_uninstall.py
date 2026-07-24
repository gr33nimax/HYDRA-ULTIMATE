from unittest.mock import patch

import pytest

from hydra.core.state import AppState
from hydra.core.uninstall import uninstall_hydra, uninstall_plan


def test_uninstall_dry_run_is_side_effect_free():
    state = AppState()
    with patch("hydra.plugins.registry.all_plugins", return_value=[]) as plugins:
        result = uninstall_hydra(
            state,
            confirmed=False,
            dry_run=True,
            keep_data=False,
        )
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert any(path.replace("\\", "/").endswith("/var/lib/hydra") for path in result["paths"])
    plugins.assert_called_once_with()


def test_uninstall_requires_explicit_confirmation():
    with patch("hydra.plugins.registry.all_plugins", return_value=[]):
        with pytest.raises(ValueError, match="--yes"):
            uninstall_hydra(AppState(), confirmed=False)


def test_keep_data_removes_data_paths_from_plan():
    with patch("hydra.plugins.registry.all_plugins", return_value=[]):
        plan = uninstall_plan(AppState(), keep_data=True)
    normalized = [path.replace("\\", "/") for path in plan["paths"]]
    assert not any(path.endswith("/var/lib/hydra") for path in normalized)
    assert not any(path.endswith("/var/log/hydra") for path in normalized)
