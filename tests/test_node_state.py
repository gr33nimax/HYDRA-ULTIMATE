"""Persisted node definitions: additive, validated, and reloadable."""

from __future__ import annotations

import json

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core import state as state_module
from hydra.core import state_format
from hydra.core.state_nodes import NodeConfig


def _write_document(document: dict) -> None:
    state_module.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state_module.STATE_FILE.write_text(
        json.dumps(document),
        encoding="utf-8",
    )


def _node(**overrides) -> NodeConfig:
    values = {
        "id": "de-1",
        "name": "de-1",
        "region": "Германия",
        "address": "203.0.113.10",
        "control_port": 8443,
        "ssh_port": 2222,
        "branch": "main",
        "revision": "a" * 40,
        "control_fingerprint": "b" * 64,
        "generation": 4,
        "published_generation": 3,
        "protocols": {
            "vless": NodeProtocolSpec(
                enabled=True,
                port=443,
                config={"domain": "de.example.com"},
            ),
        },
        "profile_names": {"vless": "Германия · VLESS"},
    }
    values.update(overrides)
    return NodeConfig(**values)


def test_document_without_nodes_still_loads():
    """Existing installations must keep working: the namespace is additive."""
    _write_document(
        {
            "format_version": state_format.STATE_FORMAT_VERSION,
            "revision": 5,
            "core": {"users": []},
            "features": {"protocols": {}},
        },
    )
    loaded = state_module.load_state()
    assert loaded.nodes == []


def test_node_survives_a_save_and_load_round_trip():
    state = state_module.load_state()
    state.nodes = [_node()]
    state_module.save_state(state)

    persisted = json.loads(state_module.STATE_FILE.read_text(encoding="utf-8"))
    assert persisted["features"]["nodes"][0]["id"] == "de-1"
    assert persisted["features"]["nodes"][0]["protocols"]["vless"]["port"] == 443
    assert persisted["features"]["nodes"][0]["control_fingerprint"] == "b" * 64
    assert persisted["features"]["nodes"][0]["ssh_port"] == 2222

    reloaded = state_module.load_state()
    assert reloaded.nodes == [_node()]


def test_published_snapshot_metadata_round_trips_additively():
    node = _node(desired_digest="d" * 64, published_digest="c" * 64)
    state = state_module.load_state()
    state.nodes = [node]
    state_module.save_state(state)

    reloaded = state_module.load_state()

    assert reloaded.nodes == [node]
    old_node = NodeConfig.from_raw({"id": "de-1", "generation": 1}, path="nodes[0]")
    assert old_node.desired_digest == ""
    assert old_node.published_digest == ""


def test_invalid_published_snapshot_digest_is_rejected():
    state = state_module.load_state()
    state.nodes = [_node(published_digest="not-a-digest")]

    with pytest.raises(ValueError, match="published_digest"):
        state_module.save_state(state)


def test_published_generation_cannot_lead_the_desired_generation():
    state = state_module.load_state()
    state.nodes = [_node(generation=1, published_generation=2)]
    with pytest.raises(ValueError, match="published_generation"):
        state_module.save_state(state)


def test_duplicate_node_ids_are_rejected():
    state = state_module.load_state()
    state.nodes = [_node(), _node(region="Нидерланды")]
    with pytest.raises(ValueError, match="repeats id"):
        state_module.save_state(state)


def test_invalid_ssh_port_is_rejected():
    state = state_module.load_state()
    state.nodes = [_node(ssh_port=0)]
    with pytest.raises(ValueError, match="ssh_port"):
        state_module.save_state(state)


def test_invalid_control_fingerprint_is_rejected():
    state = state_module.load_state()
    state.nodes = [_node(control_fingerprint="not-a-fingerprint")]
    with pytest.raises(ValueError, match="control_fingerprint"):
        state_module.save_state(state)


def test_node_profile_name_cannot_inject_a_subscription_line():
    state = state_module.load_state()
    state.nodes = [_node(profile_names={"vless": "bad\nvless://injected"})]
    with pytest.raises(ValueError):
        state_module.save_state(state)


def test_invalid_node_identifier_is_rejected():
    state = state_module.load_state()
    state.nodes = [_node(id="de 1")]
    with pytest.raises(ValueError, match="node_id"):
        state_module.save_state(state)


def test_corrupt_nodes_fall_back_to_the_previous_backup():
    _write_document(
        {
            "format_version": state_format.STATE_FORMAT_VERSION,
            "revision": 5,
            "core": {},
            "features": {"nodes": ["not-an-object"]},
        },
    )
    state_module.STATE_FILE.with_suffix(".json.bak").write_text(
        json.dumps(
            {
                "format_version": state_format.STATE_FORMAT_VERSION,
                "revision": 4,
                "core": {},
                "features": {},
            },
        ),
        encoding="utf-8",
    )
    assert state_module.load_state().revision == 4


def test_envelope_defaults_cover_every_declared_key():
    """A key added to an envelope can no longer be missing from the defaults."""
    declared = state_format._CORE_KEYS + state_format._FEATURE_KEYS
    assert set(state_format._DEFAULTS) == set(declared)
    assert state_format._DEFAULTS["nodes"] == []
    assert state_format._DEFAULTS["install"] == {}
