from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from hydra.contracts.managed_node_installation import InstallRequest
from hydra.contracts.managed_node_models import ProtocolAssignment
from hydra.contracts.managed_node_observations import NodeSample
from hydra.core import state as state_backend
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, User
from hydra.services.application import ApplicationService
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.identity import create_certificate_pair
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import SshFacts

_SHA = "a" * 40
_FINGERPRINT = "SHA256:" + "A" * 43


class StrictManagementClient:
    def __init__(self, node_id: str):
        self.node_id = node_id

    def state(self, deadline: float) -> NodeSample:
        assert deadline > 0
        return NodeSample(self.node_id, runtime={"management_api": "ready"})


class StrictSsh:
    def __init__(self):
        self.calls: list[str] = []

    def discover_host_key(self, address, port):
        assert address and port == 22
        return _FINGERPRINT

    def inspect(self, request, auth):
        self.calls.append("inspect")
        return SshFacts("ubuntu", "24.04", 0, True, False, "198.51.100.8", frozenset(), _FINGERPRINT)

    def uninstall_existing(self, plan, auth):
        raise AssertionError("no existing installation was reported")

    def bootstrap(self, plan, auth):
        self.calls.append("bootstrap")

    def provision_management(self, plan, base_certificate, auth):
        self.calls.append("provision")
        return create_certificate_pair(plan.definition.id, role="server", address=plan.definition.address)[0]

    def read_public_certificate(self, plan, auth):
        raise AssertionError("initial enrollment returns the server certificate")

    def remove_node(self, plan, auth):
        raise AssertionError("application boundary test does not remove")

    def reconcile_install_step(self, plan, operation, auth):
        return "unknown"

    def reconcile_remove(self, plan, operation, auth):
        return "unknown"


def test_application_nodes_port_owns_plan_install_list_and_restart_resume(tmp_path: Path):
    remote = StrictSsh()
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    service = ManagedNodeOperationsService(
        records=records,
        ssh=remote,
        credentials=ManagementCredentialStore(host=HostBackend(), root=tmp_path / "credentials"),
        revision_resolver=lambda _branch: _SHA,
        operation_id_factory=lambda: "install-boundary",
        client_factory=lambda definition, files, certificate: StrictManagementClient(definition.id),
        profile_reader=lambda user, state: (user.uuid, state.revision),
    )
    application = ApplicationService(
        users=cast(Any, None),
        protocols=cast(Any, None),
        apply_config=lambda _state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state=None: {},
        nodes=service,
    )
    request = InstallRequest(
        "de-1", "DE-1", "203.0.113.4", "root", "dev",
        [ProtocolAssignment("vless", {"port": 443})], _FINGERPRINT, 25555,
    )

    plan = application.nodes.plan(request, None)
    assert plan.definition.revision == _SHA
    operation = application.nodes.install(plan, None, True, False)
    assert operation.state == "running"
    assert operation.error is not None and operation.error["stage"] == "apply"
    assert application.nodes.list()[0].definition.id == "de-1"
    assert application.nodes.list()[0].sub_state == "wait"
    assert not hasattr(application.nodes, "refresh")
    assert application.nodes.profiles_for_user(User("alice@example.test", uuid="alice"), AppState()) == ("alice", 0)

    resumed = application.nodes.resume(operation.id, None)
    assert resumed.id == operation.id
    assert remote.calls == ["inspect", "bootstrap", "provision"]
