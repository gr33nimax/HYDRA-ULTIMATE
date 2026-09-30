from unittest.mock import Mock

import pytest

from hydra.contracts.node_validation import NodeContractError
from hydra.core import state as storage
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.snapshot_store import NodeSnapshotStore


def _manager(tmp_path):
    storage.save_state(AppState(nodes=[NodeConfig(id="de-1", name="Germany", address="node.example.com")]))
    client = Mock(side_effect=AssertionError("offline edit must not contact node"))
    manager = NodeManager(
        state_reader=storage.load_state,
        state_updater=storage.update_state,
        client_for=client,
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
    )
    return manager, client


def test_profile_name_change_is_local_and_empty_value_removes_override(tmp_path):
    manager, client = _manager(tmp_path)
    manager.change_profile_name("de-1", "vless", "Berlin")
    assert storage.load_state().nodes[0].profile_names == {"vless": "Berlin"}
    manager.change_profile_name("de-1", "vless", "")
    assert storage.load_state().nodes[0].profile_names == {}
    client.assert_not_called()


def test_update_target_requires_exact_sha_and_preserves_previous_target_on_error(tmp_path):
    manager, client = _manager(tmp_path)
    manager.change_update_target("de-1", branch="dev", revision="a" * 40)
    before = storage.load_state()
    with pytest.raises(NodeContractError):
        manager.change_update_target("de-1", branch="dev", revision="HEAD")
    after = storage.load_state()
    assert after.nodes[0].revision == "a" * 40
    assert after.nodes[0].branch == "dev"
    assert after.revision == before.revision
    client.assert_not_called()


def test_profile_name_rejects_invalid_key_without_persisting(tmp_path):
    manager, _ = _manager(tmp_path)
    before = storage.load_state()
    with pytest.raises(ValueError):
        manager.change_profile_name("de-1", "vless\nother", "name")
    assert storage.load_state().revision == before.revision
    assert storage.load_state().nodes[0].profile_names == {}
