import copy
from types import SimpleNamespace
from typing import Any, cast

from hydra.bootstrap import production_application
from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.core import state as state_backend
from hydra.core.host import HostBackend
from hydra.core.state import AppState, PluginState, User
from hydra.core.state_managed_nodes import ManagedNodesState, store_managed_nodes
from hydra.services.application import ApplicationService
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeIdentityStore
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService


def _application(**dependencies: Any) -> ApplicationService:
    return cast(ApplicationService, ApplicationService(**dependencies))


class _Users:
    def __init__(self):
        self.calls = []

    def list(self, state):
        return list(state.users)

    def add(self, state, user):
        self.calls.append(("add", user.email))
        return user

    def remove(self, state, email):
        self.calls.append(("remove", email))

    def block(self, state, email):
        self.calls.append(("block", email))

    def unblock(self, state, email):
        self.calls.append(("unblock", email))


def test_application_service_delegates_user_lifecycle_and_apply():
    users = _Users()
    applied = []
    app = _application(
        users=users,
        protocols=SimpleNamespace(),
        apply_config=lambda state: applied.append(state) or True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
    )
    state = AppState()
    user = User(email="alice@example.com", uuid="u1")

    assert app.add_user(state, user) is user
    app.block_user(state, user.email)
    app.unblock_user(state, user.email)
    app.remove_user(state, user.email)
    assert app.apply(state) is True
    assert [kind for kind, _ in users.calls] == ["add", "block", "unblock", "remove"]
    assert applied == [state]


def test_production_application_wires_ephemeral_node_rendering(tmp_path):
    identity = ManagedNodeProbeIdentityStore(
        host=HostBackend(),
        root=tmp_path / "managed-node",
        node_id="node-a",
    )
    expected = identity.ensure()
    application = production_application(managed_node_probe_identity=identity)
    plugins = cast(Any, application.apply_config).__self__.plugins

    state = AppState()
    contributions = plugins.runtime_contributions(state)

    assert [(user.email, user.uuid) for user in contributions.users] == [
        (expected.email, expected.uuid),
    ]
    assert state.users == []


def test_production_application_revalidates_staged_cascade_evidence(tmp_path):
    from hydra.contracts.managed_node_cascade import CascadeParticipantReceipt, CascadeParticipantRequest
    from hydra.contracts.managed_node_probe import ProbeMaterial
    from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
    from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
    from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
    from hydra.services.managed_nodes.cascade_preparation import (
        CascadePreparationEvidence,
        CascadePreparationStore,
        ManagedNodeCascadePreparationOwner,
    )
    from hydra.services.managed_nodes.cascade_rendering import CascadeTechnicalPeerMaterial
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    engine, baseline, prepared, exit_engine, exit_config = (character * 64 for character in "12345")
    route = CascadeDefinition("route-prod", "Production", "base", "exit", ["vless"])
    plan = {"cascade_id": route.id, "previous": None, "cascade": route.to_document()}
    operation = Operation("stage-prod", "cascade_save", route.id, canonical_digest(plan), "pending", plan=plan)
    state = AppState(
        protocols={
            "vless": PluginState(
                enabled=True,
                installed=True,
                port=443,
                config={
                    "domain": "entry.example.test",
                    "cert_file": "/cert.pem",
                    "key_file": "/key.pem",
                    "xhttp_mode": "stream-up",
                    "xhttp_path": "/xhttp",
                    "security": "tls",
                },
            ),
        },
    )
    store_managed_nodes(state.feature_extensions, ManagedNodesState(operations=[operation]))
    state_backend.save_state(state)
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    records.begin_step(operation.id, "snapshot")
    records.complete_step(operation.id, "snapshot")
    root = state_backend.STATE_DIR / "managed-nodes"
    credentials = CascadeCredentialStore(host=HostBackend(), root=root / "cascade-credentials")
    evidence_state = {"engine": engine, "current": baseline}

    def evidence(*_args):
        return CascadePreparationEvidence(evidence_state["engine"], baseline, prepared, evidence_state["current"])

    owner = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=state_backend.load_state,
        credentials=credentials,
        store=CascadePreparationStore(host=HostBackend(), root=root / "cascade-preparations"),
        participant_id="base",
        authenticated_participant=lambda _operation, _route: "base",
        evidence_provider=evidence,
    )
    owner.prepare(operation.id, "vless")
    participant_store = CascadeParticipantStore(host=HostBackend(), root=root / "cascade-transactions")
    participant_request = CascadeParticipantRequest(
        operation.id,
        operation.kind,
        operation.target_id,
        operation.desired_digest,
        plan,
        "base",
        "entry",
        route,
        "vless",
    )
    participant_store.snapshot(participant_request, engine, baseline, CascadeRestoreContext.empty(participant_request))
    participant_store.update(
        participant_request,
        phase="prepared",
        receipt=CascadeParticipantReceipt(
            operation.id,
            operation.desired_digest,
            route.id,
            "base",
            "entry",
            "vless",
            "prepared",
            engine,
            prepared,
        ).to_document(),
        preparation_receipt=CascadeParticipantReceipt(
            operation.id,
            operation.desired_digest,
            route.id,
            "base",
            "entry",
            "vless",
            "prepared",
            engine,
            prepared,
        ).to_document(),
    )

    def peer(_state, preparation, transit):
        outbound = {
            "type": "vless",
            "tag": "technical-peer",
            "server": "203.0.113.19",
            "server_port": 443,
            "uuid": transit.uuid,
            "tls": {"enabled": True, "server_name": "exit.example.test"},
        }
        ProbeMaterial("vless", outbound).validate()
        return CascadeTechnicalPeerMaterial(
            preparation.route.id,
            preparation.route.entry_id,
            preparation.route.exit_id,
            preparation.route.exit_id,
            "transit",
            preparation.protocol,
            preparation.operation_id,
            preparation.plan_digest,
            exit_engine,
            exit_config,
            outbound,
        )

    application = production_application(
        cascade_preparation_evidence_provider=evidence,
        cascade_technical_peer_material_provider=peer,
    )
    plugins = cast(Any, application.apply_config).__self__.plugins
    current_state = state_backend.load_state()
    staged = plugins.runtime_contributions(current_state)
    assert len(staged.users) == 1

    evidence_state["engine"] = "9" * 64
    assert plugins.runtime_contributions(current_state).users == ()
    evidence_state["engine"] = engine
    evidence_state["current"] = "8" * 64
    assert plugins.runtime_contributions(current_state).users == ()
    evidence_state["current"] = baseline
    assert len(plugins.runtime_contributions(current_state).users) == 1

    default_application = production_application()
    default_plugins = cast(Any, default_application.apply_config).__self__.plugins
    assert default_plugins.runtime_contributions(current_state).users == ()


def test_production_ordinary_apply_rejects_current_persisted_lease_before_save_or_runtime(tmp_path, monkeypatch):
    import hydra.bootstrap_application as application_wiring

    monkeypatch.setenv("HYDRA_APPLY_LOCK_FILE", str(tmp_path / "apply.lock"))
    route = CascadeDefinition("route-lease", "Leased", "base", "exit", ["vless"])
    plan = {"cascade_id": route.id, "previous": None, "cascade": route.to_document()}
    operation = Operation("stage-lease", "cascade_save", route.id, canonical_digest(plan), "pending", plan=plan)
    persisted = AppState()
    store_managed_nodes(persisted.feature_extensions, ManagedNodesState(operations=[operation]))
    state_backend.save_state(persisted)
    saved = []
    monkeypatch.setattr(application_wiring, "save_state", lambda state: saved.append(copy.deepcopy(state)))
    application = production_application()
    orchestration = cast(Any, application.apply_config).__self__
    attempted = []
    cast(Any, orchestration)._configuration_applier = lambda: SimpleNamespace(
        apply=lambda state: attempted.append(state) or False
    )
    stale = AppState()
    stale.install["caller_value"] = "must not be restored"
    before = copy.deepcopy(stale)

    assert application.apply(stale) is False

    assert stale == before
    assert saved == []
    assert attempted == []
    assert (
        state_backend.load_state().feature_extensions["managed_nodes"] == persisted.feature_extensions["managed_nodes"]
    )
    assert "cascade participant" in application.apply_error()


def test_application_service_exposes_the_new_managed_node_port():
    nodes = production_application().nodes
    app = _application(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        nodes=nodes,
    )

    assert isinstance(app.nodes, ManagedNodeOperationsService)
    assert callable(app.nodes.plan)
    assert callable(app.nodes.install)
    assert callable(app.nodes.resume)
    assert callable(app.nodes.list)
    assert callable(app.nodes.remove)
    assert not hasattr(app.nodes, "refresh")


def test_application_service_exposes_last_apply_error_without_leaking_exceptions():
    app = _application(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: False,
        last_apply_error=lambda: "configuration failed",
        plugin_statuses=lambda state: {},
    )
    assert app.apply(AppState()) is False
    assert app.apply_error() == "configuration failed"


def test_application_check_combines_validation_host_and_change_preview():
    system = SimpleNamespace(
        validate=lambda state: {"valid": True, "schema_version": state.version},
        doctor=lambda state: {"ok": True, "required_failures": []},
    )
    planner = SimpleNamespace(
        build=lambda state: {
            "valid": True,
            "plugins": ["naive"],
            "reconciliation": [],
            "tls_mux": {"ok": True},
        },
    )
    app = _application(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        system=system,
        planner=planner,
    )

    assert app.check(AppState()) == {
        "ok": True,
        "configuration": {"valid": True, "schema_version": AppState().version},
        "host": {"ok": True, "required_failures": []},
        "changes": {
            "valid": True,
            "plugins": ["naive"],
            "reconciliation": [],
            "tls_mux": {"ok": True},
        },
    }


def test_application_check_includes_tls_runtime_audit_in_result():
    app = _application(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        system=SimpleNamespace(
            validate=lambda state: {"valid": True},
            doctor=lambda state: {"ok": True},
        ),
        planner=SimpleNamespace(
            build=lambda state: {
                "valid": True,
                "tls_mux": {"ok": False, "required": True},
            },
        ),
    )

    assert app.check(AppState())["ok"] is False


def test_application_service_status_uses_injected_plugin_reader():
    calls = []
    app = _application(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: calls.append(state) or {"demo": {"running": True}},
    )
    state = AppState()

    payload = app.status(state)

    assert calls == [state]
    assert payload["runtime"]["demo"]["running"] is True


def test_production_applications_do_not_share_plugin_or_orchestrator_state():
    first = production_application()
    second = production_application()

    assert first.protocols.operations is not second.protocols.operations
    assert isinstance(first.nodes, ManagedNodeOperationsService)
    assert first.nodes is not second.nodes
    assert first.users.after_node_change() is None
    assert first.protocols.require("antidpi") is not second.protocols.require(
        "antidpi",
    )
