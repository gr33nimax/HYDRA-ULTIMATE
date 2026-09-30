"""Separate node cookies and explicit offline detach contracts."""
from unittest.mock import Mock

import pytest

from hydra.core import state as storage
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, User
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.node_traffic_accounting import apply_node_traffic_reports
from hydra.contracts.node_traffic import NodeTrafficReport, NodeTrafficUsage


def _manager(tmp_path, **kwargs):
    storage.save_state(AppState(
        users=[User(email="u@example.com", uuid="u1", traffic_used_bytes=10)],
        nodes=[NodeConfig(id="de-1", name="Germany", address="node.example.com")],
    ))
    return NodeManager(
        state_reader=storage.load_state, state_updater=storage.update_state,
        client_for=Mock(side_effect=AssertionError("must not use control API")),
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
        **kwargs,
    )


def test_detach_never_contacts_remote_and_retains_already_counted_quota(tmp_path):
    remote = Mock(side_effect=AssertionError("offline detach must not use SSH"))
    forget = Mock()
    manager = _manager(tmp_path, uninstall_remote=remote, forget_node_credentials=forget)
    storage.update_state(lambda state: apply_node_traffic_reports(state, [NodeTrafficReport(
        node_id="de-1", generation=0, users={"u1": NodeTrafficUsage(reset_epoch=0, used_bytes=25)},
    )]))
    result = manager.detach_node("de-1", confirmed=True)
    assert result == {"node_id": "de-1", "status": "detached", "remote_cleanup": False}
    saved = storage.load_state()
    assert saved.nodes == []
    assert saved.users[0].traffic_used_bytes == 35
    assert "de-1" not in saved.install["node_traffic_contributions"]
    remote.assert_not_called()
    forget.assert_called_once_with("de-1")


def test_detach_requires_confirmation_and_keeps_config_on_state_write_failure(tmp_path):
    forget = Mock()
    manager = _manager(tmp_path, forget_node_credentials=forget)
    with pytest.raises(ValueError, match="confirmation"):
        manager.detach_node("de-1", confirmed=False)
    manager.state_updater = Mock(side_effect=RuntimeError("disk full"))
    with pytest.raises(RuntimeError, match="disk full"):
        manager.detach_node("de-1", confirmed=True)
    assert len(storage.load_state().nodes) == 1
    forget.assert_not_called()


def test_node_cookie_import_uses_only_selected_target_without_state_changes(tmp_path):
    importer = Mock()
    manager = _manager(tmp_path, import_remote_cookies=importer)
    before = storage.load_state()
    manager.import_vk_cookies("de-1", "/secure/node-vk.json")
    node, source = importer.call_args.args
    assert node.id == "de-1"
    assert source == "/secure/node-vk.json"
    assert storage.load_state() == before
    assert isinstance(manager.client_for, Mock)
    manager.client_for.assert_not_called()
