from __future__ import annotations

from typing import Any, cast

import pytest

from hydra.contracts.managed_node_installation import InstallRequest
from hydra.contracts.managed_node_models import (
    CascadeDefinition,
    NodeDefinition,
    NodeDesired,
    Operation,
    ProtocolAssignment,
    UserAssignment,
)


def definition(**changes) -> NodeDefinition:
    values = {
        "id": "de-1",
        "name": "DE-1",
        "address": "203.0.113.4",
        "ssh_user": "operator",
        "branch": "dev",
        "revision": "a" * 40,
        "control_port": 24443,
        "protocols": [ProtocolAssignment("vless", {"port": 443})],
        "identity_ref": "managed-node/de-1",
    }
    values.update(changes)
    return NodeDefinition(**values)


def test_node_definition_rejects_invalid_address_port_and_control_characters():
    for invalid in (
        {"address": "not-an-ip"},
        {"control_port": 22},
        {"name": "DE-1\nroot"},
    ):
        with pytest.raises(ValueError):
            definition(**invalid).validate()


def test_node_desired_keeps_future_cascade_assignments_and_canonical_digest():
    user = UserAssignment(
        uuid="user-1",
        email="one@example.test",
        blocked=False,
        expiry_date="2030-01-01",
        traffic_limit_gb=10,
        disabled_protocols=[],
        reset_epoch=3,
    )
    cascade = CascadeDefinition("cascade-1", "EU via UK", "uk-1", "de-1", ["vless"])
    desired = NodeDesired(
        node_id="de-1",
        revision=7,
        users=[user],
        protocols=[ProtocolAssignment("vless", {"port": 443})],
        cascades=[cascade],
    )
    decoded = NodeDesired.from_document(desired.to_document())
    assert decoded.cascades == [cascade]
    assert decoded.users_digest == desired.users_digest
    assert len(desired.digest) == 64
    assert desired.to_document()["cascades"][0]["entry_id"] == "uk-1"


def test_user_expiry_wire_round_trip_preserves_date_datetime_timezone_and_z_exactly():
    for expiry in (
        "2030-01-01",
        "2030-01-01T00:00:00+05:30",
        "2030-01-01T00:00:00Z",
        "2030-01-01T00:00:00",
    ):
        assignment = UserAssignment("user-1", "one@example.test", expiry_date=expiry)
        assert UserAssignment.from_document(assignment.to_document()).expiry_date == expiry
    for expiry in (None, 42, "not-a-date", "2030-02-30", "2030-01-01T25:00:00Z"):
        with pytest.raises(ValueError):
            UserAssignment("user-1", "one@example.test", expiry_date=cast(Any, expiry)).validate()


def test_duplicate_assignment_ids_and_secret_shaped_operation_fields_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        NodeDesired(
            "de-1",
            1,
            [
                UserAssignment("same", "a@example.test"),
                UserAssignment("same", "b@example.test"),
            ],
            [],
        ).validate()
    with pytest.raises(ValueError, match="secret"):
        Operation.from_document(
            {
                "id": "op-1",
                "kind": "install",
                "target_id": "de-1",
                "desired_digest": "a" * 64,
                "state": "pending",
                "completed_steps": [],
                "error": {"stage": "ssh", "password": "never-persist"},
                "receipt": None,
                "plan": None,
                "remote_removal_confirmed": False,
                "active_step": None,
                "existing_reinstall_confirmed": False,
            }
        )


def test_operation_round_trip_has_stable_public_fields():
    operation = Operation(
        id="op-1",
        kind="install",
        target_id="de-1",
        desired_digest="a" * 64,
        state="pending",
    )
    assert Operation.from_document(operation.to_document()) == operation
    InstallRequest(
        id="de-1", name="DE-1", address="203.0.113.4", ssh_user="root",
        branch="dev", protocols=[ProtocolAssignment("vless", {"port": 443})],
        host_key_fingerprint="SHA256:" + "A" * 43,
    ).validate()
