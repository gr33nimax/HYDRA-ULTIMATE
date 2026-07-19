"""Runtime assessment separating persisted intent from host reality."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from hydra.plugins.base import PluginStatus


@dataclass(frozen=True)
class RuntimeAssessment:
    desired_enabled: bool
    installed: bool
    running: bool
    actual_state: str
    health: str
    drift: str
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def assess(status: PluginStatus, desired_enabled: bool, error: str = "") -> RuntimeAssessment:
    if error:
        return RuntimeAssessment(desired_enabled, False, False, "unknown", "unknown", "unknown", error)
    if not status.installed:
        actual_state, health = "not_installed", "missing"
    elif status.running:
        actual_state, health = "running", "healthy"
    else:
        actual_state, health = "stopped", "stopped"
    if desired_enabled and not status.installed:
        drift = "missing"
    elif desired_enabled and not status.running:
        drift = "stopped"
    elif not desired_enabled and status.running:
        drift = "unexpectedly_running"
    else:
        drift = "none"
    return RuntimeAssessment(desired_enabled, status.installed, status.running, actual_state, health, drift)
