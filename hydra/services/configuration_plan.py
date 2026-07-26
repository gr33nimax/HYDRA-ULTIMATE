"""Side-effect-free configuration planning use-case."""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping, Protocol

from hydra.contracts import ConfigFragment
from hydra.core.state_models import AppState


class ConfigurationPlanning(Protocol):
    def build(self, state: AppState) -> dict[str, Any]: ...


@dataclass(frozen=True)
class UnavailableConfigurationPlanning:
    def build(self, state: AppState) -> dict[str, Any]:
        raise RuntimeError("configuration planning service is unavailable")


@dataclass(frozen=True)
class ConfigurationPlanner:
    """Build an apply preview from explicitly supplied read-only capabilities."""

    collect_fragments: Callable[
        [AppState],
        Mapping[str, ConfigFragment],
    ]
    generate_config: Callable[
        [AppState, Mapping[str, ConfigFragment]],
        dict[str, Any],
    ]
    preflight_conflicts: Callable[[dict[str, Any]], list[str]]
    requirements: Callable[
        [AppState],
        dict[str, dict[str, list[str]]],
    ]
    reconciliation_plan: Callable[[AppState], list[Any]]
    route_audit: Callable[[AppState], Any]

    def build(self, state: AppState) -> dict[str, Any]:
        candidate = copy.deepcopy(state)
        candidate.network.tproxy_enabled = True
        fragments = dict(self.collect_fragments(candidate))
        config = self.generate_config(candidate, fragments)
        conflicts = list(self.preflight_conflicts(config))
        reconciliation = self.reconciliation_plan(state)
        return {
            "valid": not conflicts,
            "conflicts": conflicts,
            "plugins": sorted(fragments),
            "requirements": self.requirements(candidate),
            "reconciliation": [asdict(action) for action in reconciliation],
            "tls_mux": self.route_audit(state).as_dict(),
            "changes": {
                "inbounds": len(config.get("inbounds", [])),
                "outbounds": len(config.get("outbounds", [])),
                "route_rules": len(
                    config.get("route", {}).get("rules", []),
                ),
                "tproxy_ports": sorted(
                    {
                        port
                        for fragment in fragments.values()
                        for port in fragment.nft_tproxy_ports
                    },
                ),
            },
        }


__all__ = [
    "ConfigurationPlanner",
    "ConfigurationPlanning",
    "UnavailableConfigurationPlanning",
]
