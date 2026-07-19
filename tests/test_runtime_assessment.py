from hydra.plugins.base import PluginStatus
from hydra.plugins.runtime import assess


def test_desired_enabled_but_service_stopped_is_drift():
    result = assess(PluginStatus(installed=True, enabled=False, running=False), True)
    assert (result.actual_state, result.health, result.drift) == ("stopped", "stopped", "stopped")


def test_disabled_but_running_is_drift():
    result = assess(PluginStatus(installed=True, enabled=True, running=True), False)
    assert (result.actual_state, result.health, result.drift) == ("running", "healthy", "unexpectedly_running")


def test_missing_desired_service_is_missing_drift():
    result = assess(PluginStatus(installed=False, enabled=False, running=False), True)
    assert (result.actual_state, result.health, result.drift) == ("not_installed", "missing", "missing")


def test_status_error_is_unknown_not_missing():
    result = assess(PluginStatus(installed=False, enabled=False, running=False), True, "systemd unavailable")
    assert (result.actual_state, result.health, result.drift) == ("unknown", "unknown", "unknown")
