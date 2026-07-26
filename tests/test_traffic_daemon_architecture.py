"""Architecture and extension contracts for traffic accounting."""
from __future__ import annotations

from types import SimpleNamespace

from hydra.core.state import AppState, PluginState, User
from hydra.services.traffic_accounting import apply_connection_snapshot
from hydra.services.traffic_attribution import (
    ConnectionAttributor,
    TrafficEvidence,
)
from hydra.services.traffic_daemon_infrastructure import (
    collect_traffic_evidence,
)
from hydra.services.traffic_daemon_unit import TrafficDaemonUnitManager


def test_new_protocol_with_authenticated_metadata_needs_no_daemon_branch():
    user = User(email="custom@example.com", uuid="custom-user")
    state = AppState(
        users=[user],
        protocols={"custom": PluginState(enabled=True)},
    )

    changed = apply_connection_snapshot(
        state,
        [
            {
                "id": "custom-connection",
                "metadata": {
                    "inboundTag": "custom-in",
                    "user": user.email,
                },
                "upload": 120,
                "download": 380,
            },
        ],
        TrafficEvidence(),
    )

    assert changed is True
    assert user.credentials["custom"]["traffic_used_bytes"] == 500


def test_protocol_can_inject_unusual_user_attribution():
    user = User(email="resolver@example.com", uuid="resolver-user")
    state = AppState(
        users=[user],
        protocols={"custom": PluginState(enabled=True)},
    )
    attributor = ConnectionAttributor(
        resolvers={
            "custom": (
                lambda connection, _state, _evidence: (
                    user.email
                    if connection["metadata"].get("token") == "known"
                    else None
                )
            ),
        },
    )

    changed = apply_connection_snapshot(
        state,
        [
            {
                "id": "custom-token",
                "metadata": {
                    "inboundTag": "custom-in",
                    "token": "known",
                },
                "upload": 50,
                "download": 70,
            },
        ],
        TrafficEvidence(),
        attributor=attributor,
    )

    assert changed is True
    assert user.credentials["custom"]["traffic_used_bytes"] == 120


def test_all_attribution_indexes_share_one_journal_read():
    journal = "\n".join(
        [
            "INFO [1 0ms] inbound/anytls[anytls-in]: "
            "inbound connection from 127.0.0.1:1234",
            "INFO [1 1ms] inbound/anytls[anytls-in]: "
            "[alice] inbound connection to example.com:443",
            "INFO [2 0ms] inbound/hysteria2[hysteria2-in]: "
            "inbound connection from 198.51.100.5:4321",
            "INFO [2 1ms] inbound/hysteria2[hysteria2-in]: "
            "[bob] inbound connection to example.com:443",
        ],
    )

    class Host:
        def __init__(self):
            self.calls = 0

        def run(self, *_args, **_kwargs):
            self.calls += 1
            return SimpleNamespace(returncode=0, stdout=journal)

    host = Host()
    evidence = collect_traffic_evidence(host)

    assert host.calls == 1
    assert evidence.source_ports["anytls"]["1234"] == "alice"
    assert evidence.sources["hysteria2"][("198.51.100.5", "4321")] == "bob"


def test_daemon_revision_covers_extracted_component_modules(tmp_path):
    services = tmp_path / "hydra" / "services"
    services.mkdir(parents=True)
    (services / "traffic_daemon.py").write_text("facade", encoding="utf-8")
    dependency = services / "traffic_attribution.py"
    dependency.write_text("first", encoding="utf-8")

    first = TrafficDaemonUnitManager._daemon_revision(tmp_path)
    dependency.write_text("second", encoding="utf-8")
    second = TrafficDaemonUnitManager._daemon_revision(tmp_path)

    assert first != second
