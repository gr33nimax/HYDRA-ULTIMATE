from hydra.core.state_models import AppState, User
from hydra.contracts.managed_node_observations import TrafficSample
from hydra.services.managed_nodes.accounting import apply_traffic_samples


def test_cascade_entry_is_charged_once_but_transit_probe_and_other_user_are_not():
    state = AppState(users=[User("one@example.test", "user-one")])
    samples = [
        TrafficSample("user-one", "direct-vless", "direct", 0, "epoch-a", 40),
        TrafficSample("user-one", "route-a-entry", "cascade_entry", 0, "epoch-a", 100),
        TrafficSample("user-one", "route-a-transit", "transit", 0, "epoch-a", 100),
        TrafficSample("user-one", "probe", "probe", 0, "epoch-a", 999),
        TrafficSample("other-user", "route-a-entry", "cascade_entry", 0, "epoch-a", 500),
    ]

    apply_traffic_samples(state, "entry", samples)
    assert state.users[0].traffic_used_bytes == 140
