from unittest.mock import MagicMock

from hydra.core.state import AppState, PluginState, User
from hydra.services.active_connections import tracked_active_connections
from hydra.services.traffic import (
    refresh_user_traffic,
    check_traffic_limits,
    protocol_totals,
    reset_global_report_traffic,
    reset_user_traffic,
)
from hydra.services.traffic_accounting import apply_connection_snapshot
from hydra.services.traffic_attribution import TrafficEvidence, evidence_from_journal


class FakeTrafficProtocols:
    def __init__(self, plugins=()):
        self.plugins = {plugin.meta.name: plugin for plugin in plugins}

    def enabled_names(self, state: AppState) -> set[str]:
        return {name for name, protocol in state.protocols.items() if protocol.enabled and name in self.plugins}

    def traffic(self, state: AppState, name: str) -> dict[str, int]:
        return self.plugins[name].traffic(state)

    def traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> dict[str, int] | None:
        return self.plugins[name].traffic_snapshot(state)

    def aggregate_traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> int | None:
        return self.plugins[name].aggregate_traffic_snapshot(state)

    def ingest_traffic(
        self,
        state: AppState,
        name: str,
        cursors: dict,
    ) -> None:
        self.plugins[name].ingest_traffic(state, cursors)


def test_first_connection_poll_initializes_report_before_crediting_bytes():
    user = User(email="u@example.com", uuid="u1")
    state = AppState(users=[user], protocols={"anytls": PluginState(enabled=True)})
    connection = {
        "id": "first",
        "metadata": {"user": user.email, "inboundTag": "anytls-in"},
        "upload": 100,
        "download": 200,
    }
    apply_connection_snapshot(state, [connection], TrafficEvidence())
    assert user.traffic_used_bytes == 300
    assert protocol_totals(state) == {"anytls": 300}
    connection["download"] = 250
    apply_connection_snapshot(state, [connection], TrafficEvidence())
    assert protocol_totals(state) == {"anytls": 350}


def test_reset_user_preserves_legacy_global_total_before_first_poll():
    user = User(
        email="u@example.com", uuid="u1", traffic_used_bytes=300, credentials={"anytls": {"traffic_used_bytes": 300}}
    )
    state = AppState(users=[user])
    reset_user_traffic(state, user.email)
    assert user.traffic_used_bytes == 0
    assert protocol_totals(state) == {"anytls": 300}


def test_resettable_snapshot_is_accumulated_monotonically():
    user = User(email="u@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"amneziawg": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "amneziawg"
    plugin.traffic_snapshot.side_effect = [
        {user.email: 100},
        {user.email: 150},
        {user.email: 20},
    ]
    plugin.aggregate_traffic_snapshot.return_value = None
    protocols = FakeTrafficProtocols([plugin])
    refresh_user_traffic(state, protocols=protocols)
    refresh_user_traffic(state, protocols=protocols)
    refresh_user_traffic(state, protocols=protocols)

    assert user.credentials["amneziawg"]["traffic_used_bytes"] == 170
    assert user.traffic_used_bytes == 170


def test_qwdtt_aggregate_is_monotonic_without_per_user_attribution():
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})
    plugin = MagicMock()
    plugin.meta.name = "wdtt"
    plugin.traffic_snapshot.return_value = None
    plugin.aggregate_traffic_snapshot.side_effect = [
        100,
        150,
        20,
        None,
        40,
    ]

    protocols = FakeTrafficProtocols([plugin])
    for _ in range(5):
        refresh_user_traffic(state, protocols=protocols)

    stats = state.install["protocol_traffic_totals"]["wdtt"]
    assert stats["traffic_used_bytes"] == 190
    assert stats["traffic_last_raw_bytes"] == 40
    assert protocol_totals(state)["wdtt"] == 190
    assert state.users == []


def test_custom_plugin_snapshot_needs_no_service_allowlist():
    user = User(email="custom@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"custom": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "custom"
    plugin.traffic_snapshot.return_value = {user.email: 125}
    plugin.aggregate_traffic_snapshot.return_value = None

    refresh_user_traffic(
        state,
        protocols=FakeTrafficProtocols([plugin]),
    )

    assert user.credentials["custom"]["traffic_used_bytes"] == 125


def test_limit_is_reached_at_exact_boundary():
    limit = 1073741824
    user = User(
        email="u@example.com",
        uuid="u1",
        traffic_limit_gb=1,
        traffic_used_bytes=limit,
    )
    state = AppState(users=[user])
    assert check_traffic_limits(
        state,
        protocols=FakeTrafficProtocols(),
    ) == [user.email]


def test_global_reset_starts_new_report_without_resetting_user_quota():
    user = User(email="u@example.com", uuid="u1", traffic_limit_gb=1)
    state = AppState(
        users=[user],
        protocols={"naive": PluginState(enabled=True)},
    )
    user.traffic_used_bytes = 300
    user.credentials["naive"] = {
        "traffic_used_bytes": 300,
        "traffic_last_raw_bytes": 300,
    }

    reset_global_report_traffic(state)

    assert protocol_totals(state) == {"naive": 0}
    assert user.traffic_used_bytes == 300
    assert user.credentials["naive"]["traffic_used_bytes"] == 300
    plugin = MagicMock()
    plugin.meta.name = "naive"
    plugin.traffic_snapshot.return_value = {user.email: 350}
    plugin.aggregate_traffic_snapshot.return_value = None
    refresh_user_traffic(state, protocols=FakeTrafficProtocols([plugin]))
    assert user.traffic_used_bytes == 350
    assert protocol_totals(state) == {"naive": 50}


def test_user_reset_retains_baselines_and_does_not_resurrect_active_bytes():
    user = User(
        email="u@example.com",
        uuid="u1",
        traffic_limit_gb=1,
        expiry_date="2030-01-01T00:00:00+00:00",
        blocked=True,
        credentials={"anytls": {"password": "secret"}},
    )
    state = AppState(
        users=[user],
        protocols={"anytls": PluginState(enabled=True)},
    )
    connection = {
        "id": "c1",
        "metadata": {"user": user.email, "inboundTag": "anytls-in"},
        "upload": 100,
        "download": 200,
    }
    assert apply_connection_snapshot(state, [connection], TrafficEvidence())
    state.install["traffic_log_cursors"] = {"naive": {"inode:1": 42}}

    reset_user_traffic(state, user.email)

    assert user.traffic_limit_gb == 1
    assert user.blocked
    assert user.expiry_date == "2030-01-01T00:00:00+00:00"
    assert user.credentials["anytls"]["password"] == "secret"
    assert state.install["traffic_log_cursors"] == {"naive": {"inode:1": 42}}
    assert apply_connection_snapshot(state, [connection], TrafficEvidence()) is False
    assert user.traffic_used_bytes == 0
    connection["download"] = 250
    assert apply_connection_snapshot(state, [connection], TrafficEvidence())
    assert user.traffic_used_bytes == 50


def test_user_reset_keeps_snapshot_baseline_and_global_report():
    user = User(email="u@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"amneziawg": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "amneziawg"
    plugin.traffic_snapshot.side_effect = [{user.email: 300}] * 2 + [
        {user.email: 350},
    ]
    plugin.aggregate_traffic_snapshot.return_value = None
    protocols = FakeTrafficProtocols([plugin])

    refresh_user_traffic(state, protocols=protocols)
    report_before_reset = protocol_totals(state).copy()
    reset_user_traffic(state, user.email)
    refresh_user_traffic(state, protocols=protocols)

    assert user.traffic_used_bytes == 0
    assert protocol_totals(state) == report_before_reset
    refresh_user_traffic(state, protocols=protocols)
    assert user.traffic_used_bytes == 50
    assert protocol_totals(state)["amneziawg"] == 350


def test_active_connections_group_only_current_attributed_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time

    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "a": {"user": "u@example.com", "protocol": "anytls", "download": 100, "upload": 20, "missed_polls": 0},
        "b": {"user": "u@example.com", "protocol": "anytls", "download": 50, "upload": 10, "missed_polls": 0},
        "stale": {"user": "old@example.com", "protocol": "anytls", "download": 999, "upload": 999, "missed_polls": 1},
        "unknown": {"user": "", "protocol": "mieru", "download": 999, "upload": 999, "missed_polls": 0},
    }
    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["email"] == "u@example.com"
    assert rows[0]["rx"] == 150
    assert rows[0]["tx"] == 30
    assert rows[0]["connections"] == 2


def test_active_connections_include_attributed_shadowtls_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time

    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "shadow": {
            "user": "shadow@example.com",
            "protocol": "shadowtls",
            "download": 480,
            "upload": 120,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["plugin"] == "shadowtls"
    assert rows[0]["email"] == "shadow@example.com"
    assert rows[0]["rx"] == 480
    assert rows[0]["tx"] == 120


def test_active_connections_include_attributed_hysteria2_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time

    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "hysteria2": {
            "user": "hy2@example.com",
            "protocol": "hysteria2",
            "download": 500,
            "upload": 200,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["plugin"] == "hysteria2"
    assert rows[0]["email"] == "hy2@example.com"
    assert rows[0]["rx"] == 500
    assert rows[0]["tx"] == 200


def test_active_connections_include_a_custom_attributed_protocol():
    state = AppState()
    state.network.clash_api_enabled = True
    import time

    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "custom": {
            "user": "custom@example.com",
            "protocol": "custom",
            "download": 300,
            "upload": 100,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    assert tracked_active_connections(state) == [
        {
            "plugin": "custom",
            "email": "custom@example.com",
            "online": True,
            "rx": 300,
            "tx": 100,
            "connections": 1,
            "last_handshake": int(
                state.install["traffic_connection_counters"]["custom"]["seen_at"],
            ),
            "traffic_scope": "active",
        },
    ]


def test_vless_cdn_connection_is_credited_by_its_inbound_tag():
    user = User(email="cdn@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"vless_cdn": PluginState(enabled=True)},
    )
    connection = {
        "id": "cdn-1",
        "metadata": {"user": user.email, "inboundTag": "vless-cdn-in"},
        "upload": 120,
        "download": 880,
    }

    assert apply_connection_snapshot(state, [connection], TrafficEvidence())
    assert user.traffic_used_bytes == 1000
    assert user.credentials["vless_cdn"]["traffic_used_bytes"] == 1000
    assert state.install["traffic_connection_counters"]["cdn-1"]["protocol"] == "vless_cdn"


def test_vless_cdn_journal_evidence_credits_only_the_cdn_identity():
    user = User(email="cdn@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"vless_cdn": PluginState(enabled=True)},
    )
    state.network.clash_api_enabled = True
    connection = {
        "id": "cdn-journal",
        "metadata": {
            "inboundTag": "vless-cdn-in",
            "user": "",
            "sourceIP": "127.0.0.1",
            "sourcePort": "43123",
        },
        "upload": 120,
        "download": 880,
    }
    evidence = evidence_from_journal(
        [
            "INFO [123456 0ms] inbound/vless[vless-cdn-in]: inbound connection from 127.0.0.1:43123",
            "INFO [123456 1ms] inbound/vless[vless-cdn-in]: "
            "[cdn@example.com] inbound connection to origin.example.com:443",
        ],
    )
    # Evidence is published per inbound, so the CDN identity holds only CDN records.
    assert evidence.source_ports["vless_cdn"] == {"43123": "cdn@example.com"}
    assert evidence.source_ports["vless"] == {}

    assert apply_connection_snapshot(state, [connection], evidence)
    assert user.traffic_used_bytes == 1000
    assert user.credentials["vless_cdn"]["traffic_used_bytes"] == 1000
    assert "vless" not in user.credentials
    rows = tracked_active_connections(state)
    assert [row["plugin"] for row in rows] == ["vless_cdn"]
    assert rows[0]["email"] == "cdn@example.com"


def test_regular_vless_journal_evidence_stays_out_of_the_cdn_bucket():
    user = User(email="vless@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"vless": PluginState(enabled=True)},
    )
    state.network.clash_api_enabled = True
    connection = {
        "id": "vless-journal",
        "metadata": {
            "inboundTag": "vless-xhttp-in",
            "user": "",
            "sourceIP": "127.0.0.1",
            "sourcePort": "43124",
        },
        "upload": 300,
        "download": 700,
    }
    evidence = evidence_from_journal(
        [
            "INFO [123456 0ms] inbound/vless[vless-xhttp-in]: inbound connection from 127.0.0.1:43124",
            "INFO [123456 1ms] inbound/vless[vless-xhttp-in]: "
            "[vless@example.com] inbound connection to cp.cloudflare.com:80",
        ],
    )

    assert evidence.source_ports["vless"] == {"43124": "vless@example.com"}
    assert "vless_cdn" not in evidence.source_ports

    assert apply_connection_snapshot(state, [connection], evidence)
    assert user.credentials["vless"]["traffic_used_bytes"] == 1000
    assert "vless_cdn" not in user.credentials
    rows = tracked_active_connections(state)
    assert [row["plugin"] for row in rows] == ["vless"]
    assert rows[0]["email"] == "vless@example.com"


def test_recycled_loopback_port_cannot_move_vless_evidence_to_the_cdn_identity():
    """A regular VLESS log record must never credit a CDN connection on a reused port."""
    cdn = User(email="cdn@example.com", uuid="u1")
    regular = User(email="vless@example.com", uuid="u2")
    state = AppState(
        users=[cdn, regular],
        protocols={
            "vless": PluginState(enabled=True),
            "vless_cdn": PluginState(enabled=True),
        },
    )
    state.network.clash_api_enabled = True
    # The loopback relay can hand the same source port to a CDN connection after a
    # regular VLESS connection closed; the journal record must not follow it.
    cdn_connection = {
        "id": "recycled-cdn",
        "metadata": {
            "inboundTag": "vless-cdn-in",
            "user": "",
            "sourceIP": "127.0.0.1",
            "sourcePort": "43123",
        },
        "upload": 120,
        "download": 880,
    }
    regular_connection = {
        "id": "original-vless",
        "metadata": {
            "inboundTag": "vless-xhttp-in",
            "user": "",
            "sourceIP": "127.0.0.1",
            "sourcePort": "43123",
        },
        "upload": 300,
        "download": 700,
    }
    evidence = evidence_from_journal(
        [
            "INFO [123456 0ms] inbound/vless[vless-xhttp-in]: inbound connection from 127.0.0.1:43123",
            "INFO [123456 1ms] inbound/vless[vless-xhttp-in]: "
            "[vless@example.com] inbound connection to cp.cloudflare.com:80",
        ],
    )

    assert evidence.source_ports["vless"] == {"43123": "vless@example.com"}
    assert "vless_cdn" not in evidence.source_ports

    assert apply_connection_snapshot(
        state,
        [cdn_connection, regular_connection],
        evidence,
    )
    assert cdn.traffic_used_bytes == 0
    assert "vless_cdn" not in cdn.credentials
    assert regular.credentials["vless"]["traffic_used_bytes"] == 1000
    # The regular VLESS record must not land in any vless_cdn bucket.
    assert "vless_cdn" not in regular.credentials
    rows = tracked_active_connections(state)
    assert [(row["plugin"], row["email"]) for row in rows] == [
        ("vless", "vless@example.com"),
    ]
    cdn_record = state.install["traffic_connection_counters"]["recycled-cdn"]
    assert cdn_record["user"] == ""
    assert cdn_record["protocol"] == "vless_cdn"


def test_vless_cdn_without_matching_journal_evidence_stays_uncredited():
    user = User(email="cdn@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"vless_cdn": PluginState(enabled=True)},
    )
    state.network.clash_api_enabled = True
    connection = {
        "id": "cdn-unmatched",
        "metadata": {
            "inboundTag": "vless-cdn-in",
            "user": "",
            "sourcePort": "43125",
        },
        "upload": 120,
        "download": 880,
    }
    evidence = evidence_from_journal(
        [
            "INFO [123456 0ms] inbound/vless[vless-cdn-in]: inbound connection from 127.0.0.1:43123",
            "INFO [123456 1ms] inbound/vless[vless-cdn-in]: "
            "[cdn@example.com] inbound connection to origin.example.com:443",
        ],
    )

    assert apply_connection_snapshot(state, [connection], evidence) is False
    assert user.traffic_used_bytes == 0
    assert user.credentials.get("vless_cdn", {}).get("traffic_used_bytes", 0) == 0
    assert tracked_active_connections(state) == []
    record = state.install["traffic_connection_counters"]["cdn-unmatched"]
    assert record["user"] == ""
    assert record["protocol"] == "vless_cdn"
    empty = evidence_from_journal(())
    assert empty.source_ports == {"anytls": {}, "vless": {}}
    assert "vless_cdn" not in empty.source_ports


def test_an_awg_peer_is_attributed_by_its_tunnel_address():
    """A tunnel peer has no stable source port: the address it holds inside the tunnel identifies it."""
    from hydra.core.state import AppState, PluginState, User
    from hydra.services.traffic_attribution import ConnectionAttributor, TrafficEvidence
    from hydra.services.traffic_daemon import _awg_source_addresses

    protocol = PluginState(
        installed=True,
        config={"protocol_mode": "2.0", "profiles": {"desktop": {"network": "10.67.67.0/24"}}},
    )
    alice = User(email="alice@example.com", uuid="u1")
    alice.credentials["amneziawg"] = {"address_octet": "3"}
    mallory = User(email="mallory@example.com", uuid="u2", blocked=True)
    mallory.credentials["amneziawg"] = {"address_octet": "9"}
    state = AppState(protocols={"amneziawg": protocol}, users=[alice, mallory])

    addresses = _awg_source_addresses(state)
    assert addresses == {"10.67.67.3": "alice@example.com"}

    connection = {"metadata": {"sourceIP": "10.67.67.3", "sourcePort": "44321"}}
    assert (
        ConnectionAttributor._evidence_user(
            "amneziawg",
            connection,
            TrafficEvidence(source_addresses={"amneziawg": addresses}),
        )
        == "alice@example.com"
    )

    unknown = {"metadata": {"sourceIP": "10.67.67.77", "sourcePort": "44321"}}
    assert (
        ConnectionAttributor._evidence_user(
            "amneziawg",
            unknown,
            TrafficEvidence(source_addresses={"amneziawg": addresses}),
        )
        == ""
    )
