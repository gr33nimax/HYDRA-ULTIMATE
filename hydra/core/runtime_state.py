"""Immutable runtime facts kept separate from persisted application state."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from hydra.core.state import AppState


@dataclass(frozen=True)
class RuntimePluginState:
    desired_enabled: bool = False
    installed: bool = False
    running: bool = False
    actual_state: str = "unknown"
    health: str = "unknown"
    drift: str = "unknown"
    port: int = 0
    error: str = ""

    @classmethod
    def from_status(cls, status: Mapping[str, Any]) -> "RuntimePluginState":
        return cls(
            desired_enabled=bool(status.get("desired_enabled", status.get("enabled", False))),
            installed=bool(status.get("installed", False)),
            running=bool(status.get("running", False)),
            actual_state=str(status.get("actual_state", "unknown")),
            health=str(status.get("health", "unknown")),
            drift=str(status.get("drift", "unknown")),
            port=int(status.get("port", 0) or 0),
            error=str(status.get("error", "") or ""),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeSnapshot:
    plugins: dict[str, RuntimePluginState] = field(default_factory=dict)

    @classmethod
    def from_statuses(cls, statuses: Mapping[str, Mapping[str, Any]]) -> "RuntimeSnapshot":
        return cls({name: RuntimePluginState.from_status(status) for name, status in statuses.items()})

    @classmethod
    def collect(cls, state: AppState) -> "RuntimeSnapshot":
        from hydra.plugins.registry import status_all

        return cls.from_statuses(status_all(state))

    def as_dict(self) -> dict[str, dict[str, Any]]:
        return {name: status.as_dict() for name, status in self.plugins.items()}

    def drifts(self) -> dict[str, str]:
        return {
            name: status.drift
            for name, status in self.plugins.items()
            if status.drift != "none"
        }
