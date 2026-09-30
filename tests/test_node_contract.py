"""Contract guard for base ↔ node data: nothing extra, nothing malformed."""

from __future__ import annotations

import pytest

from hydra.contracts.node_export import (
    NodeClientExport,
    NodeClientExportUser,
    NodeClientProfile,
    NodeContractError,
    missing_exported_users,
)
from hydra.contracts.node_snapshot import (
    NodeDesiredSnapshot,
    NodeProtocolSpec,
    NodeUserProjection,
)
from hydra.contracts.node_validation import (
    MAX_USERS_PER_SNAPSHOT,
    NODE_CONTRACT_VERSION,
)


def _snapshot(**overrides) -> NodeDesiredSnapshot:
    values = {
        "node_id": "de-1",
        "generation": 3,
        "users": (
            NodeUserProjection(email="alice@example.com", uuid="11111111-2222"),
            NodeUserProjection(email="bob@example.com", uuid="33333333-4444", blocked=True),
        ),
        "protocols": {
            "vless": NodeProtocolSpec(enabled=True, port=443, config={"domain": "de.example.com"}),
        },
    }
    values.update(overrides)
    return NodeDesiredSnapshot(**values)


def test_snapshot_survives_a_document_round_trip():
    snapshot = _snapshot()
    restored = NodeDesiredSnapshot.from_document(snapshot.to_document())
    assert restored == snapshot


def test_protocol_document_carries_no_node_local_runtime_state():
    document = NodeProtocolSpec(enabled=True, port=8443).to_document()
    assert set(document) == {"enabled", "port", "config"}
    assert not hasattr(NodeProtocolSpec(), "installed")


def test_desired_snapshot_carries_no_credentials():
    document = _snapshot().to_document()
    assert set(document) == {"contract_version", "node_id", "generation", "users", "protocols"}
    assert set(document["users"][0]) == {
        "email",
        "uuid",
        "blocked",
        "expiry_date",
        "disabled_protocols",
        "traffic_limit_gb",
        "traffic_reset_epoch",
    }


def test_unknown_snapshot_field_is_rejected():
    document = _snapshot().to_document()
    document["credentials"] = {"vless": {"uuid": "smuggled"}}
    with pytest.raises(NodeContractError, match="unsupported fields: credentials"):
        NodeDesiredSnapshot.from_document(document)


def test_user_projection_round_trip_preserves_local_traffic_limit():
    restored = NodeUserProjection.from_document(
        {
            "email": "alice@example.com",
            "uuid": "u1",
            "traffic_limit_gb": 12.5,
            "traffic_reset_epoch": 3,
        },
    )
    assert restored.traffic_limit_gb == 12.5
    assert restored.to_document()["traffic_reset_epoch"] == 3


def test_node_protocol_config_rejects_node_local_secrets_recursively():
    with pytest.raises(NodeContractError, match="node-local secret"):
        NodeProtocolSpec(config={"tls": {"server_private_key": "base-secret"}}).validate()


def test_negative_or_non_finite_user_limit_is_rejected():
    for value in (-1, float("inf"), float("nan"), True):
        with pytest.raises(NodeContractError, match="traffic_limit_gb"):
            NodeUserProjection(email="alice", uuid="u1", traffic_limit_gb=value).validate()


def test_future_contract_version_is_rejected():
    document = _snapshot().to_document()
    document["contract_version"] = NODE_CONTRACT_VERSION + 1
    with pytest.raises(NodeContractError, match="contract_version"):
        NodeDesiredSnapshot.from_document(document)


def test_duplicate_users_are_rejected():
    with pytest.raises(NodeContractError, match="repeats uuid"):
        _snapshot(
            users=(
                NodeUserProjection(email="a@example.com", uuid="same"),
                NodeUserProjection(email="b@example.com", uuid="same"),
            ),
        ).validate()


def test_port_out_of_range_is_rejected():
    with pytest.raises(NodeContractError, match=r"protocols\.vless\.port"):
        _snapshot(protocols={"vless": NodeProtocolSpec(port=70000)}).validate()


def test_user_count_limit_is_enforced():
    users = tuple(
        NodeUserProjection(email=f"u{index}@example.com", uuid=f"uuid-{index}")
        for index in range(MAX_USERS_PER_SNAPSHOT + 1)
    )
    with pytest.raises(NodeContractError, match="limit"):
        _snapshot(users=users).validate()


def test_link_with_a_newline_is_rejected():
    """A newline would inject a second entry into a base64 subscription."""
    with pytest.raises(NodeContractError, match="single line"):
        NodeClientProfile(
            protocol="vless",
            links=("vless://payload\nvless://injected",),
        ).validate()


def test_link_without_a_scheme_is_rejected():
    with pytest.raises(NodeContractError, match="absolute URI"):
        NodeClientProfile(protocol="vless", links=("not-a-link",)).validate()


def test_export_entry_must_match_its_user_uuid():
    with pytest.raises(NodeContractError, match="does not match user"):
        NodeClientExport(
            node_id="de-1",
            generation=1,
            users={"other": NodeClientExportUser(uuid="alice")},
        ).validate()


def test_export_round_trip_keeps_singbox_documents():
    export = NodeClientExport(
        node_id="de-1",
        generation=3,
        users={
            "alice": NodeClientExportUser(
                uuid="alice",
                profiles=(
                    NodeClientProfile(
                        protocol="hysteria2",
                        profile="mobile",
                        links=("hysteria2://a@de.example.com:443?sni=de.example.com",),
                        singbox=({"type": "hysteria2", "tag": "de-1-hy2"},),
                    ),
                ),
            ),
        },
    )
    restored = NodeClientExport.from_document(export.to_document())
    assert restored == export


def test_duplicate_profile_in_one_user_is_rejected():
    profile = NodeClientProfile(protocol="vless")
    with pytest.raises(NodeContractError, match="repeats profile"):
        NodeClientExportUser(uuid="alice", profiles=(profile, profile)).validate()


def test_missing_material_is_reported_but_blocked_users_are_exempt():
    snapshot = _snapshot()
    export = NodeClientExport(
        node_id="de-1",
        generation=3,
        users={"11111111-2222": NodeClientExportUser(uuid="11111111-2222")},
    )
    assert missing_exported_users(snapshot, export) == ()


def test_active_user_without_material_is_reported():
    snapshot = _snapshot(
        users=(NodeUserProjection(email="alice@example.com", uuid="11111111-2222"),),
    )
    export = NodeClientExport(node_id="de-1", generation=3, users={})
    assert missing_exported_users(snapshot, export) == ("11111111-2222",)


def test_export_from_another_node_is_rejected():
    with pytest.raises(NodeContractError, match="does not belong"):
        missing_exported_users(
            _snapshot(),
            NodeClientExport(node_id="nl-1", generation=3),
        )
