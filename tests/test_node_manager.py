from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest

from hydra.contracts.node_export import NodeClientExport, NodeClientExportUser, NodeClientProfile
from hydra.contracts.node_snapshot import NodeProtocolSpec, NodeUserProjection
from hydra.contracts.node_traffic import NodeTrafficReport, NodeTrafficUsage
from hydra.contracts.node_validation import NODE_CONTRACT_VERSION
from hydra.core import state as state_module
from hydra.core.state_models import AppState, User
from hydra.core.state_nodes import NodeConfig
from hydra.core.host import HostBackend
from hydra.services.nodes.credentials import NodeControlCredentials
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.reconciler import NodeSnapshotReconciler
from hydra.services.nodes.snapshot_store import NodeSnapshotStore


class FakeNodeBootstrap:
    def __init__(self, *, node_fingerprint="b" * 64):
        self.node_fingerprint = node_fingerprint
        self.install_request = None
        self.provision_request = None

    def install(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        branch: str,
        revision: str,
        confirm_fingerprint: Callable[[str], bool],
        ssh_user: str = "root",
        auth=None,
    ) -> str:
        self.install_request = (node_id, address, ssh_port, branch, revision, ssh_user)
        fingerprint = "SHA256:confirmed-host-key"
        if not confirm_fingerprint(fingerprint):
            raise PermissionError("SSH host fingerprint was not confirmed")
        return fingerprint

    def provision_control_identity(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        base_url: str,
        control_port: int,
        ssh_user: str = "root",
        auth=None,
    ) -> NodeControlCredentials:
        self.provision_request = (node_id, address, ssh_port, base_url, control_port, ssh_user)
        return NodeControlCredentials(
            client_certificate=Path("client.crt"),
            client_private_key=Path("client.key"),
            node_certificate=Path("node.crt"),
            base_fingerprint="c" * 64,
            node_fingerprint=self.node_fingerprint,
        )


class FakeControlClient:
    def __init__(self, *, node_id="de-1", fail_after_apply=False, on_apply=None):
        self.node_id = node_id
        self.generation = 0
        self.fail_after_apply = fail_after_apply
        self.on_apply = on_apply
        self.applied = []
        self.events = []
        self.upgrade_requests = []
        self.exported = NodeClientExport(node_id=node_id, generation=0)
        self.traffic_users = {}

    def health(self):
        self.events.append("health")
        return {
            "ok": True,
            "node_id": self.node_id,
            "generation": self.generation,
            "contract_version": NODE_CONTRACT_VERSION,
        }

    def diagnostics(self):
        return {"last_error": ""}

    def apply(self, snapshot):
        self.events.append("apply")
        self.applied.append(deepcopy(snapshot))
        if snapshot.generation > self.generation:
            self.generation = snapshot.generation
            users = {
                item.uuid: NodeClientExportUser(
                    uuid=item.uuid,
                    # A real node exports one profile per protocol it serves this
                    # user: an export with no profiles is not a published node.
                    profiles=tuple(
                        NodeClientProfile(
                            protocol=name,
                            profile="",
                            links=(f"vless://{item.uuid}@node.example.com:443",),
                        )
                        for name, spec in sorted(snapshot.protocols.items())
                        if spec.enabled and name not in item.disabled_protocols
                    ),
                )
                for item in snapshot.users
                if not item.blocked
            }
            self.exported = NodeClientExport(
                node_id=self.node_id,
                generation=self.generation,
                users=users,
            )
        if self.on_apply is not None:
            self.on_apply(snapshot)
            self.on_apply = None
        if self.fail_after_apply:
            self.fail_after_apply = False
            raise OSError("simulated lost response")
        return {"generation": self.generation, "already_applied": len(self.applied) > 1}

    def export(self):
        self.events.append("export")
        return self.exported

    def traffic_report(self):
        return NodeTrafficReport(
            node_id=self.node_id,
            generation=self.generation,
            users=deepcopy(self.traffic_users),
        )

    def upgrade(self, *, branch, revision):
        self.upgrade_requests.append((branch, revision))
        return {"node_id": self.node_id, "status": "scheduled", "branch": branch, "revision": revision}


def _saved_node_state():
    state = AppState(
        users=[
            User(
                email="alice@example.com",
                uuid="user-1",
                expiry_date="2030-01-01",
                disabled_protocols=["anytls"],
                traffic_limit_gb=12.5,
            ),
            User(email="blocked@example.com", uuid="user-2", blocked=True),
        ],
        nodes=[
            NodeConfig(
                id="de-1",
                name="Germany",
                region="Germany",
                address="node.example.com",
                control_fingerprint="a" * 64,
                protocols={"vless": NodeProtocolSpec(enabled=True, port=443, config={"server": "edge"})},
            ),
        ],
    )
    state_module.save_state(state)


def _reconciler(tmp_path, client):
    return NodeSnapshotReconciler(
        state_updater=state_module.update_state,
        client_for=lambda node: client,
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
    )


def _manager(tmp_path, client, **options):
    return NodeManager(
        state_reader=state_module.load_state,
        state_updater=state_module.update_state,
        client_for=lambda node: client,
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
        **options,
    )


def test_traffic_reports_reconcile_reset_epoch_before_collecting_absolute_usage(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    client.traffic_users = {
        "user-1": NodeTrafficUsage(reset_epoch=0, used_bytes=4096),
    }
    manager = _manager(tmp_path, client)

    reports = manager.traffic_reports()

    assert len(reports) == 1
    assert reports[0].node_id == "de-1"
    assert reports[0].generation == state_module.load_state().nodes[0].generation == 1
    assert reports[0].users["user-1"].used_bytes == 4096


def test_refresh_applies_complete_projection_and_publishes_only_confirmed_export(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    reconciler = _reconciler(tmp_path, client)

    result = reconciler.refresh("de-1")

    state = state_module.load_state()
    node = state.nodes[0]
    assert result.status == "published"
    assert result.generation == 1
    assert node.generation == node.published_generation == 1
    assert node.published_digest == result.sha256
    assert len(node.desired_digest) == 64
    assert client.applied[0].users == (
        NodeUserProjection(
            email="alice@example.com",
            uuid="user-1",
            blocked=False,
            expiry_date="2030-01-01",
            disabled_protocols=("anytls",),
            traffic_limit_gb=12.5,
        ),
        NodeUserProjection(email="blocked@example.com", uuid="user-2", blocked=True),
    )
    export = reconciler.snapshot_store.load(node.id, node.published_generation, node.published_digest)
    assert export.uuids() == ("user-1",)


def test_lost_apply_response_retries_the_same_generation(tmp_path):
    _saved_node_state()
    client = FakeControlClient(fail_after_apply=True)
    reconciler = _reconciler(tmp_path, client)

    with pytest.raises(OSError, match="lost response"):
        reconciler.refresh("de-1")
    assert state_module.load_state().nodes[0].published_generation == 0

    result = reconciler.refresh("de-1")

    assert [snapshot.generation for snapshot in client.applied] == [1, 1]
    assert result.generation == 1
    assert state_module.load_state().nodes[0].published_generation == 1


def test_desired_state_change_during_remote_apply_prevents_stale_publication(tmp_path):
    _saved_node_state()

    def change_user(_snapshot):
        def block_user(state):
            state.users[0].blocked = True

        state_module.update_state(block_user)

    client = FakeControlClient(on_apply=change_user)
    reconciler = _reconciler(tmp_path, client)

    with pytest.raises(RuntimeError, match="desired state changed"):
        reconciler.refresh("de-1")
    state = state_module.load_state()
    assert state.nodes[0].published_generation == 0
    assert state.users[0].blocked is True

    result = reconciler.refresh("de-1")

    assert result.generation == 2
    assert client.applied[-1].users[0].blocked is True
    assert state_module.load_state().nodes[0].published_generation == 2


def test_published_export_is_loaded_locally_without_contacting_node(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    manager = _manager(tmp_path, client)
    manager.refresh("de-1")
    events = list(client.events)

    export = manager.published_export(state_module.load_state(), "de-1")

    assert export is not None
    assert export.generation == 1
    assert client.events == events


def test_node_rename_is_persisted_without_requiring_connectivity(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    renamed = manager.change_name("de-1", "Berlin", region="Germany North")

    assert renamed.name == "Berlin"
    assert state_module.load_state().nodes[0].region == "Germany North"
    assert client.events == []


def test_protocol_change_keeps_offline_intent_without_publishing_it(tmp_path):
    """A node that is offline must not lose the operator's edit.

    The edit is desired configuration, so it is saved; nothing reaches the node and
    nothing is published until a real contact, which the unchanged generation shows.
    """
    _saved_node_state()
    client = FakeControlClient()
    client.health = lambda: (_ for _ in ()).throw(OSError("offline"))
    manager = _manager(tmp_path, client)

    with pytest.raises(OSError, match="offline"):
        manager.change_protocol("de-1", "vless", NodeProtocolSpec(enabled=False, port=443))

    state = state_module.load_state()
    assert state.nodes[0].protocols["vless"].enabled is False
    assert state.nodes[0].published_generation == 0
    assert state.nodes[0].published_digest == ""

    saved = manager.save_protocol("de-1", "vless", NodeProtocolSpec(enabled=False, port=443))
    assert saved["saved"] is True
    assert saved["applied"] is False
    assert saved["error"] == "OSError"


def test_protocol_change_applies_and_publishes_before_reporting_success(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    result = manager.change_protocol("de-1", "vless", NodeProtocolSpec(enabled=False, port=443))

    assert result.status == "published"
    assert state_module.load_state().nodes[0].protocols["vless"].enabled is False
    assert client.events.index("apply") < client.events.index("export")


def test_update_schedules_the_persisted_exact_revision(tmp_path):
    _saved_node_state()
    state = state_module.load_state()
    state.nodes[0].branch = "release"
    state.nodes[0].revision = "a" * 40
    state_module.save_state(state)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    result = manager.update("de-1")

    assert result["status"] == "scheduled"
    assert client.upgrade_requests == [("release", "a" * 40)]


def test_background_reconcile_keeps_base_user_change_when_node_is_offline(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    client.health = lambda: (_ for _ in ()).throw(OSError("offline"))
    manager = _manager(tmp_path, client)

    results = manager.reconcile_all()

    assert results["de-1"]["status"] == "failed"
    assert [user.uuid for user in state_module.load_state().users] == ["user-1", "user-2"]


def test_reconciling_two_nodes_does_not_stale_the_first_published_snapshot(tmp_path):
    _saved_node_state()

    def add_second_node(state):
        second = deepcopy(state.nodes[0])
        second.id = "nl-1"
        second.name = "Netherlands"
        second.region = "Netherlands"
        second.address = "node2.example.com"
        second.control_fingerprint = "b" * 64
        state.nodes.append(second)

    state_module.update_state(add_second_node)
    clients = {"de-1": FakeControlClient(), "nl-1": FakeControlClient(node_id="nl-1")}
    manager = NodeManager(
        state_reader=state_module.load_state,
        state_updater=state_module.update_state,
        client_for=lambda node: clients[node.id],
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
    )

    initial = manager.reconcile_all()
    repeated = manager.reconcile_all()

    assert {node_id: result["status"] for node_id, result in initial.items()} == {
        "de-1": "published",
        "nl-1": "published",
    }
    assert {node_id: result["status"] for node_id, result in repeated.items()} == {
        "de-1": "unchanged",
        "nl-1": "unchanged",
    }
    assert [len(client.applied) for client in clients.values()] == [1, 1]


def test_add_node_pins_ssh_provisions_control_identity_and_publishes_initial_snapshot(tmp_path):
    state_module.save_state(AppState(users=[User(email="alice@example.com", uuid="user-1")]))
    client = FakeControlClient()
    bootstrap = FakeNodeBootstrap()
    manager = _manager(
        tmp_path,
        client,
        bootstrap=bootstrap,
        uninstall_remote=lambda node: None,
        forget_node_credentials=lambda node_id: None,
    )
    node = NodeConfig(
        id="de-1",
        name="Germany",
        region="Germany",
        address="node.example.com",
        branch="release",
        revision="a" * 40,
        protocols={"vless": NodeProtocolSpec(enabled=True, port=443)},
    )
    confirmed = []

    result = manager.add_node(
        node,
        base_url="https://base.example.com:9444",
        confirm_fingerprint=lambda fingerprint: confirmed.append(fingerprint) or True,
    )

    saved = state_module.load_state().nodes[0]
    assert result.status == "published"
    assert bootstrap.install_request == ("de-1", "node.example.com", 22, "release", "a" * 40, "root")
    assert bootstrap.provision_request == (
        "de-1",
        "node.example.com",
        22,
        "https://base.example.com:9444",
        9444,
        "root",
    )
    assert confirmed == ["SHA256:confirmed-host-key"]
    assert saved.control_fingerprint == "b" * 64
    assert saved.published_generation == 1
    assert len(client.applied) == 1


def test_add_node_rejects_unconfirmed_ssh_host_before_provisioning(tmp_path):
    state_module.save_state(AppState())
    bootstrap = FakeNodeBootstrap()
    manager = _manager(
        tmp_path,
        FakeControlClient(),
        bootstrap=bootstrap,
        uninstall_remote=lambda node: None,
        forget_node_credentials=lambda node_id: None,
    )
    node = NodeConfig(
        id="de-1",
        name="Germany",
        address="node.example.com",
        revision="a" * 40,
    )

    with pytest.raises(PermissionError, match="not confirmed"):
        manager.add_node(
            node,
            base_url="https://base.example.com:9444",
            confirm_fingerprint=lambda fingerprint: False,
        )

    assert bootstrap.provision_request is None
    assert state_module.load_state().nodes == []


def test_remove_node_requires_pinned_remote_success_before_local_cleanup(tmp_path):
    _saved_node_state()
    client = FakeControlClient()
    events = []
    manager = _manager(
        tmp_path,
        client,
        uninstall_remote=lambda node: events.append(("remote", node.id)),
        forget_node_credentials=lambda node_id: events.append(("local", node_id)),
    )
    manager.refresh("de-1")

    result = manager.remove_node("de-1", confirmed=True)

    assert result["status"] == "removed"
    assert events == [("remote", "de-1"), ("local", "de-1")]
    assert state_module.load_state().nodes == []


def test_remove_node_remote_failure_preserves_configuration_and_credentials(tmp_path):
    _saved_node_state()
    forgotten = []

    def fail_uninstall(node):
        raise OSError("SSH unavailable")

    manager = _manager(
        tmp_path,
        FakeControlClient(),
        uninstall_remote=fail_uninstall,
        forget_node_credentials=forgotten.append,
    )

    with pytest.raises(OSError, match="SSH unavailable"):
        manager.remove_node("de-1", confirmed=True)

    assert [node.id for node in state_module.load_state().nodes] == ["de-1"]
    assert forgotten == []


def test_publication_refuses_an_export_that_carries_no_profiles(tmp_path):
    """ "Published" is the promise that subscriptions can read the node's profiles."""
    _saved_node_state()
    client = FakeControlClient()

    def apply(snapshot):
        # The node accepted the generation and answered with users it serves nothing for.
        client.exported = NodeClientExport(
            node_id="de-1",
            generation=snapshot.generation,
            users={item.uuid: NodeClientExportUser(uuid=item.uuid) for item in snapshot.users if not item.blocked},
        )

    client.on_apply = apply
    reconciler = _reconciler(tmp_path, client)

    with pytest.raises(RuntimeError, match="no client profiles"):
        reconciler.refresh("de-1")

    node = state_module.load_state().nodes[0]
    assert node.published_generation == 0
    assert node.published_digest == ""
    assert list((tmp_path / "exports" / "de-1").glob("*.json")) == []


def test_partial_protocol_coverage_publishes_and_reports_the_gap(tmp_path):
    """One transport whose prerequisites are unmet must not cost the node the rest."""
    state = AppState(
        users=[User(email="alice@example.com", uuid="user-1")],
        nodes=[
            NodeConfig(
                id="de-1",
                name="Germany",
                address="node.example.com",
                control_fingerprint="a" * 64,
                protocols={"vless": NodeProtocolSpec(enabled=True, port=443)},
            ),
        ],
    )
    state_module.save_state(state)
    client = FakeControlClient()
    client.exported = NodeClientExport(
        node_id="de-1",
        generation=1,
        users={
            "user-1": NodeClientExportUser(
                uuid="user-1",
                profiles=(NodeClientProfile(protocol="vless", profile="", links=("vless://node",)),),
            ),
        },
    )
    reconciler = _reconciler(tmp_path, client)

    def apply(snapshot):
        # The node serves VLESS but its Calls pool is not ready yet.
        client.exported = NodeClientExport(
            node_id="de-1",
            generation=snapshot.generation,
            users={
                item.uuid: NodeClientExportUser(
                    uuid=item.uuid,
                    profiles=tuple(
                        NodeClientProfile(protocol=name, profile="", links=(f"{name}://node",))
                        for name in sorted(snapshot.protocols)
                        if name == "vless"
                    ),
                )
                for item in snapshot.users
            },
        )

    client.on_apply = apply

    def reserve(state_):
        node = state_.nodes[0]
        node.protocols["calls"] = NodeProtocolSpec(enabled=True, port=56002)

    state_module.update_state(reserve)
    result = reconciler.refresh("de-1")

    assert result.status == "published"
    assert result.coverage == {"calls": 0, "vless": 1}
    assert result.warnings == ("protocols_without_profiles=calls",)
    assert state_module.load_state().nodes[0].published_generation >= 1


def test_node_operations_record_what_was_last_seen_outside_desired_state(tmp_path):
    """Observations live beside state.json: reachability must never become desired config."""
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)

    result = manager.refresh("de-1")

    observation = manager.observations()["de-1"]
    assert result.status == "published"
    assert observation.control == "ok"
    assert observation.published_generation == 1
    assert observation.coverage == {"vless": 1}
    assert observation.message == ""
    assert observation.checked_at

    # The store is a runtime projection: it never touches the persisted configuration.
    assert state_module.load_state().nodes[0].published_generation == 1


def test_a_failed_operation_records_the_stage_that_failed(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)
    client.health = lambda: {
        "ok": True,
        "node_id": "de-1",
        "generation": 0,
        "contract_version": NODE_CONTRACT_VERSION - 1,
    }

    with pytest.raises(RuntimeError):
        manager.refresh("de-1")

    observation = manager.observations()["de-1"]
    assert observation.control == "error"
    assert observation.stage == "connect"
    assert observation.code == "health_or_contract"
    assert observation.published_generation == 0


def test_check_reports_the_nodes_own_apply_error_as_reachability_ok(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    client.diagnostics = lambda: {"last_error": "Режим 3.1: S3=0 меньше 12"}
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)

    manager.check("de-1")

    observation = manager.observations()["de-1"]
    assert observation.control == "ok"
    assert observation.stage == "apply"
    assert observation.code == "node_apply_error"
    assert "S3=0" in observation.message


def test_removing_a_node_forgets_its_observation(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    store.succeeded("de-1", published_generation=1)
    manager = _manager(
        tmp_path,
        client,
        observations=store,
        uninstall_remote=lambda node: None,
        forget_node_credentials=lambda node_id: None,
    )

    manager.remove_node("de-1", confirmed=True)

    assert manager.observations() == {}


def test_health_readback_records_the_revision_the_node_reports(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    client.health = lambda: {
        "ok": True,
        "node_id": "de-1",
        "generation": 1,
        "contract_version": NODE_CONTRACT_VERSION,
        "revision": "c" * 40,
    }
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)
    target = "a" * 40
    state_module.update_state(lambda current: setattr(current.nodes[0], "revision", target))

    manager.check("de-1")

    observation = manager.observations()["de-1"]
    assert observation.installed_revision == "c" * 40
    assert observation.target_revision == target
    # Asked for one revision, running another: the update has not landed yet.
    assert observation.upgrade == "pending"


def test_a_node_running_the_requested_revision_reports_the_update_complete(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    revision = "a" * 40
    client = FakeControlClient()
    client.health = lambda: {
        "ok": True,
        "node_id": "de-1",
        "generation": 1,
        "contract_version": NODE_CONTRACT_VERSION,
        "revision": revision,
    }
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)
    state_module.update_state(lambda current: setattr(current.nodes[0], "revision", revision))

    manager.check("de-1")

    observation = manager.observations()["de-1"]
    assert observation.upgrade == "complete"


def test_resume_connects_an_installed_node_without_running_the_installer_again(tmp_path):
    state_module.save_state(AppState(users=[User(email="alice@example.com", uuid="user-1")]))
    client = FakeControlClient()
    bootstrap = FakeNodeBootstrap()
    manager = _manager(
        tmp_path,
        client,
        bootstrap=bootstrap,
        uninstall_remote=lambda node: None,
        forget_node_credentials=lambda node_id: None,
    )
    node = NodeConfig(
        id="de-1",
        name="Germany",
        address="node.example.com",
        branch="release",
        revision="a" * 40,
        protocols={"vless": NodeProtocolSpec(enabled=True, port=443)},
    )
    confirmed = []

    result = manager.resume_node(
        node,
        base_url="https://base.example.com:9444",
        confirm_fingerprint=lambda fingerprint: confirmed.append(fingerprint) or True,
    )

    saved = state_module.load_state().nodes[0]
    assert result.status == "published"
    # The whole point: an existing installation is never installed twice.
    assert bootstrap.install_request is None
    assert bootstrap.provision_request == (
        "de-1",
        "node.example.com",
        22,
        "https://base.example.com:9444",
        9444,
        "root",
    )
    # No new host key is trusted: provisioning runs with StrictHostKeyChecking=yes against
    # the pin the first install established, so resuming cannot silently adopt another machine.
    assert confirmed == []
    assert saved.control_fingerprint == "b" * 64
    assert saved.published_generation == 1


def test_resume_forwards_password_channel_and_progress_to_real_onboarding(tmp_path, monkeypatch):
    from hydra.services.nodes.ssh_auth import SshPasswordAuth

    state_module.save_state(AppState(users=[User(email="alice@example.com", uuid="user-1")]))
    client = FakeControlClient()
    bootstrap = FakeNodeBootstrap()
    provision = bootstrap.provision_control_identity
    used_auth = []

    def provision_with_auth(**kwargs):
        used_auth.append(kwargs["auth"])
        return provision(**kwargs)

    monkeypatch.setattr(bootstrap, "provision_control_identity", provision_with_auth)
    manager = _manager(tmp_path, client, bootstrap=bootstrap)
    auth = SshPasswordAuth("test-password")  # Not started: the fake never opens SSH.
    stages = []
    node = NodeConfig(
        id="de-1",
        address="node.example.com",
        revision="a" * 40,
        protocols={"vless": NodeProtocolSpec(enabled=True, port=443)},
    )

    result = manager.resume_node(
        node,
        base_url="https://base.example.com:9444",
        confirm_fingerprint=lambda fingerprint: True,
        auth=auth,
        progress=stages.append,
    )

    assert result.status == "published"
    assert used_auth == [auth]
    assert stages == ["ssh", "identity", "register", "publish"]
    assert bootstrap.install_request is None
    assert state_module.load_state().nodes[0].published_generation == 1


def test_resume_refuses_a_node_that_is_already_managed(tmp_path):
    _saved_node_state()
    manager = _manager(tmp_path, FakeControlClient())

    with pytest.raises(ValueError, match="already exists"):
        manager.resume_node(
            NodeConfig(id="de-1", address="node.example.com"),
            base_url="https://base.example.com:9444",
            confirm_fingerprint=lambda fingerprint: True,
        )


def test_resume_failure_does_not_claim_the_node_was_installed(tmp_path):
    state_module.save_state(AppState())
    bootstrap = FakeNodeBootstrap()
    bootstrap.provision_control_identity = lambda **kwargs: (_ for _ in ()).throw(OSError("ssh refused"))
    manager = _manager(
        tmp_path,
        FakeControlClient(),
        bootstrap=bootstrap,
        uninstall_remote=lambda node: None,
        forget_node_credentials=lambda node_id: None,
    )

    with pytest.raises(RuntimeError, match="must already be installed"):
        manager.resume_node(
            NodeConfig(id="de-1", address="node.example.com", branch="release", revision="a" * 40),
            base_url="https://base.example.com:9444",
            confirm_fingerprint=lambda fingerprint: True,
        )

    assert state_module.load_state().nodes == []


def test_an_unchanged_reconcile_keeps_the_coverage_it_already_knows(tmp_path):
    """ "Unchanged" carries no new counts; wiping them made a serving node look empty."""
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)

    first = manager.refresh("de-1")
    assert first.status == "published"
    assert manager.observations()["de-1"].coverage == {"vless": 1}

    second = manager.refresh("de-1")

    assert second.status == "unchanged"
    assert manager.observations()["de-1"].coverage == {"vless": 1}


def test_refresh_surfaces_the_nodes_own_apply_error(tmp_path):
    """A node answers health while its last apply failed: the base must not call that clean."""
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    client.diagnostics = lambda: {"last_error": "Режим 3.1: S3=0 меньше 12"}
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)

    manager.refresh("de-1")

    observation = manager.observations()["de-1"]
    assert observation.control == "ok"
    assert observation.stage == "apply"
    assert observation.code == "node_apply_error"
    assert "S3=0" in observation.message


def test_a_node_that_recovered_stops_reporting_the_old_error(tmp_path):
    from hydra.services.nodes.observation import NodeObservationStore

    _saved_node_state()
    client = FakeControlClient()
    client.diagnostics = lambda: {"last_error": "Режим 3.1: S3=0 меньше 12"}
    store = NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json")
    manager = _manager(tmp_path, client, observations=store)
    manager.refresh("de-1")
    assert manager.observations()["de-1"].message

    client.diagnostics = lambda: {"last_error": ""}
    manager.refresh("de-1")

    observation = manager.observations()["de-1"]
    assert observation.message == ""
    assert observation.code == ""
