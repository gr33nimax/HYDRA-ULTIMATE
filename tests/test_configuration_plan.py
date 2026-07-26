from dataclasses import dataclass

from hydra.contracts import ConfigFragment
from hydra.core.state import AppState
from hydra.services.configuration_plan import ConfigurationPlanner


@dataclass(frozen=True)
class _Action:
    plugin: str
    operation: str


class _RouteAudit:
    def as_dict(self):
        return {"valid": True}


def test_configuration_plan_uses_a_copy_and_collects_all_read_models():
    state = AppState()
    seen = {}

    def collect(candidate):
        seen["candidate"] = candidate
        assert candidate.network.tproxy_enabled is True
        return {
            "mock": ConfigFragment(nft_tproxy_ports=[443, 8443]),
        }

    planner = ConfigurationPlanner(
        collect_fragments=collect,
        generate_config=lambda candidate, fragments: {
            "inbounds": [{}],
            "outbounds": [{}, {}],
            "route": {"rules": [{}, {}, {}]},
        },
        preflight_conflicts=lambda config: [],
        requirements=lambda candidate: {"mock": {"missing_commands": []}},
        reconciliation_plan=lambda current: [_Action("mock", "enable")],
        route_audit=lambda current: _RouteAudit(),
    )

    result = planner.build(state)

    assert seen["candidate"] is not state
    assert state.network.tproxy_enabled is False
    assert result["valid"] is True
    assert result["plugins"] == ["mock"]
    assert result["reconciliation"] == [
        {"plugin": "mock", "operation": "enable"},
    ]
    assert result["changes"] == {
        "inbounds": 1,
        "outbounds": 2,
        "route_rules": 3,
        "tproxy_ports": [443, 8443],
    }
