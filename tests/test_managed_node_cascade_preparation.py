from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any, cast
from pathlib import Path

import pytest

from hydra.contracts.managed_node_models import (
    CascadeDefinition,
    NodeDefinition,
    Operation,
    ProtocolAssignment,
    canonical_digest,
)
from hydra.core.host import HostBackend
from hydra.core.state_managed_nodes import ManagedNodesState, managed_nodes_from_extensions, store_managed_nodes
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.container import PluginContainer
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_leases import cascade_participants
from hydra.services.managed_nodes.cascade_preparation import (
    CascadePreparationEvidence,
    CascadePreparationStore,
    CascadeTechnicalPreparation,
    ManagedNodeCascadePreparationOwner,
)
from hydra.services.managed_nodes.cascade_rendering import (
    CascadeTechnicalPeerMaterial,
    ManagedNodeCascadeRenderer,
)
from hydra.services.managed_nodes.cascades import ManagedNodeCascadeService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.rendering import production_runtime_contributions
from hydra.utils.crypto import derive_hex_key

_ENGINE = "1" * 64
_BASELINE = "2" * 64
_PREPARED = "3" * 64
_EXIT_ENGINE = "4" * 64
_EXIT_CONFIG = "5" * 64
_REVISION = "a" * 40


class _Host(HostBackend):
    pass


def _route(*, entry: str = "base", exit: str = "exit", protocols=None) -> CascadeDefinition:
    return CascadeDefinition("route-stage", "Stage", entry, exit, list(protocols or ["vless"]))


def _plan(route: CascadeDefinition) -> dict:
    return {"cascade_id": route.id, "previous": None, "cascade": route.to_document()}


def _operation(route: CascadeDefinition, operation_id: str = "stage-1") -> Operation:
    plan = _plan(route)
    return Operation(operation_id, "cascade_save", route.id, canonical_digest(plan), "pending", plan=plan)


def _state(route: CascadeDefinition, *, users: list[User] | None = None) -> AppState:
    protocols = {}
    if "vless" in route.protocols:
        protocols["vless"] = PluginState(
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
        )
    if "anytls" in route.protocols:
        protocols["anytls"] = PluginState(
            enabled=True,
            installed=True,
            port=8443,
            config={"domain": "entry.example.test"},
        )
    state = AppState(protocols=protocols, users=list(users or []))
    namespace = ManagedNodesState(operations=[_operation(route)])
    store_managed_nodes(state.feature_extensions, namespace)
    return state


def _records(state: AppState) -> ManagedNodeRecords:
    def update(mutator):
        result = mutator(state)
        state.revision += 1
        return copy.deepcopy(state), result

    return ManagedNodeRecords(state_reader=lambda: copy.deepcopy(state), state_updater=update)


def _confirm_snapshots(records: ManagedNodeRecords, operation_id: str = "stage-1") -> None:
    operation = records.find_operation(operation_id)
    assert operation is not None
    if "snapshot" not in operation.completed_steps:
        records.begin_step(operation_id, "snapshot")
        records.complete_step(operation_id, "snapshot")


def _owner(tmp_path: Path, state: AppState, participant_id: str, evidence_state: dict | None = None):
    evidence_state = evidence_state if evidence_state is not None else {}
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "credentials")
    store = CascadePreparationStore(host=_Host(), root=tmp_path / "preparations")
    records = _records(state)

    def evidence(_state, _operation, _route, _protocol, _participant, _role, _scope):
        return CascadePreparationEvidence(
            evidence_state.get("engine", _ENGINE),
            _BASELINE,
            _PREPARED,
            evidence_state.get("current", _BASELINE),
        )

    owner = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=lambda: copy.deepcopy(state),
        credentials=credentials,
        store=store,
        participant_id=participant_id,
        authenticated_participant=lambda _operation, _route: evidence_state.get("authenticated", participant_id),
        evidence_provider=None if evidence_state.get("missing_provider") else evidence,
    )
    return owner, records, credentials, store, evidence_state


def _peer(_state, preparation, transit):
    protocol = preparation.protocol
    outbound = {
        "type": protocol,
        "tag": "remote-technical-client",
        "server": "203.0.113.19",
        "server_port": 443,
        "tls": {"enabled": True, "server_name": "exit.example.test"},
    }
    outbound["uuid" if protocol == "vless" else "password"] = (
        transit.uuid if protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)
    )
    return CascadeTechnicalPeerMaterial(
        preparation.route.id,
        preparation.route.entry_id,
        preparation.route.exit_id,
        preparation.route.exit_id,
        "transit",
        protocol,
        preparation.operation_id,
        preparation.plan_digest,
        _EXIT_ENGINE,
        _EXIT_CONFIG,
        outbound,
    )


def _renderer(owner, credentials, participant_id: str, *, peer=True, engines=None):
    return ManagedNodeCascadeRenderer(
        participant_id=participant_id,
        credentials=credentials,
        engine_fingerprints_provider=lambda _state, _route: engines or {participant_id: _ENGINE},
        technical_preparation_provider=owner.preparations_for_render,
        technical_peer_material_provider=_peer if peer else None,
    )


def test_uncommitted_candidate_renders_technical_only_without_final_permit_or_business_users(tmp_path: Path):
    route = _route()
    state = _state(route)
    owner, records, credentials, store, _evidence = _owner(tmp_path, state, "base")
    _confirm_snapshots(records)
    preparation = owner.prepare("stage-1", "vless")
    renderer = _renderer(owner, credentials, "base")
    container = PluginContainer([VlessXhttpPlugin()], host=_Host(), runtime_contributions=renderer.render)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        fragments = cast(dict[str, Any], container.collect_fragments(state))
        from hydra.core.singbox_config import generate_config

        config = generate_config(state, fragments)

    staged = next(user for user in fragments["vless"].inbounds[0]["users"] if user["name"].startswith("cascade-"))
    cascade_rules = [rule for rule in config["route"]["rules"] if rule.get("auth_user") == [staged["name"]]]
    assert staged["uuid"] != ""
    assert cascade_rules[0]["outbound"].startswith("cascade-stage-")
    assert cascade_rules[1] == {"auth_user": [staged["name"]], "action": "reject"}
    assert all("business" not in str(rule) for rule in cascade_rules)
    assert managed_nodes_from_extensions(state.feature_extensions).cascades == []
    assert state.users == []
    assert preparation.plan_digest == _operation(route).desired_digest
    assert store.load("stage-1", route.id, "base", "vless") == preparation


def test_technical_subjects_are_operation_role_and_protocol_separated(tmp_path: Path):
    store = CascadeCredentialStore(host=_Host(), root=tmp_path / "credentials")
    scope = store.prepare("route-stage")
    entry = scope.technical_subject("base", "vless", "entry", "stage-1")
    transit = scope.technical_subject("exit", "vless", "transit", "stage-1")
    next_operation = scope.technical_subject("base", "vless", "entry", "stage-2")
    other_protocol = scope.technical_subject("base", "anytls", "entry", "stage-1")

    assert len({entry.uuid, transit.uuid, next_operation.uuid, other_protocol.uuid}) == 4
    assert "business" not in repr(entry)
    assert entry.credentials == transit.credentials == {}


def test_exit_technical_context_needs_no_remote_definition_inventory_and_routes_direct(tmp_path: Path):
    route = _route(entry="remote-entry", exit="local-exit")
    state = _state(route)
    owner, records, credentials, _store, _evidence = _owner(tmp_path, state, "local-exit")
    _confirm_snapshots(records)
    owner.prepare("stage-1", "vless")

    contributions = _renderer(owner, credentials, "local-exit").render(state)

    assert len(contributions.users) == 1
    subject = contributions.users[0]
    assert subject.protocols == ("vless",)
    assert contributions.fragments["managed_node_cascades"].outbounds == []
    assert contributions.fragments["managed_node_cascades"].route_rules == [
        {"auth_user": [subject.email], "outbound": "direct"},
    ]
    assert managed_nodes_from_extensions(state.feature_extensions).definitions == []


def test_two_protocol_technical_subjects_and_opposite_transit_routes_stay_scoped(tmp_path: Path):
    route = _route(protocols=["vless", "anytls"])
    state = _state(route)
    owner, records, credentials, _store, _evidence = _owner(tmp_path, state, "base")
    _confirm_snapshots(records)
    owner.prepare("stage-1", "vless")
    owner.prepare("stage-1", "anytls")
    renderer = _renderer(owner, credentials, "base")
    container = PluginContainer(
        [VlessXhttpPlugin(), AnyTLSPlugin()],
        host=_Host(),
        runtime_contributions=renderer.render,
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        fragments = cast(dict[str, Any], container.collect_fragments(state))

    vless_user = fragments["vless"].inbounds[0]["users"][0]
    anytls_user = fragments["anytls"].inbounds[0]["users"][0]
    assert vless_user["name"] != anytls_user["name"]
    cascade_fragment = fragments["managed_node_cascades"]
    assert {outbound["type"] for outbound in cascade_fragment.outbounds} == {"vless", "anytls"}
    assert {tuple(rule["auth_user"]) for rule in cascade_fragment.route_rules if "auth_user" in rule} == {
        (vless_user["name"],),
        (anytls_user["name"],),
    }
    assert state.users == []


def test_production_runtime_contributor_consumes_owner_revalidated_evidence(tmp_path: Path):
    route = _route()
    state = _state(route)
    owner, records, _credentials, _store, evidence = _owner(tmp_path, state, "base")
    root = tmp_path / "production"
    owner.credentials = CascadeCredentialStore(host=_Host(), root=root / "cascade-credentials")
    owner.store = CascadePreparationStore(host=_Host(), root=root / "cascade-preparations")
    _confirm_snapshots(records)
    owner.prepare("stage-1", "vless")
    contributor = production_runtime_contributions(
        host=_Host(),
        root=root,
        preparation_owner=owner,
        technical_peer_material_provider=_peer,
    )

    staged = contributor(state)
    assert len(staged.users) == 1
    assert "managed_node_cascades" in staged.fragments

    evidence["engine"] = "9" * 64
    assert contributor(state).users == ()
    evidence["engine"] = _ENGINE
    evidence["current"] = "8" * 64
    assert contributor(state).users == ()
    evidence["current"] = _BASELINE
    assert len(contributor(state).users) == 1


def test_preparation_store_paths_hash_the_complete_scope_tuple(tmp_path: Path):
    store = CascadePreparationStore(host=_Host(), root=tmp_path / "preparations")
    first_route = CascadeDefinition("c", "First", "base", "exit", ["vless"])
    second_route = CascadeDefinition("b-c", "Second", "base", "exit", ["vless"])
    first = CascadeTechnicalPreparation(
        first_route, "vless", "a-b", "a" * 64, "exit", "transit", _ENGINE, _BASELINE, _PREPARED
    )
    second = CascadeTechnicalPreparation(
        second_route, "vless", "a", "b" * 64, "exit", "transit", _ENGINE, _BASELINE, _PREPARED
    )

    assert store.save(first) == first
    assert store.save(second) == second
    assert store.load("a-b", "c", "exit", "vless") == first
    assert store.load("a", "b-c", "exit", "vless") == second
    assert len(list((tmp_path / "preparations").glob("*.json"))) == 2


def test_production_preparation_wiring_stays_unavailable_without_trusted_evidence(tmp_path: Path):
    route = _route()
    state = _state(route)
    root = tmp_path / "managed-nodes"
    records = _records(state)
    owner = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=lambda: copy.deepcopy(state),
        credentials=CascadeCredentialStore(host=_Host(), root=root / "cascade-credentials"),
        store=CascadePreparationStore(host=_Host(), root=root / "cascade-preparations"),
        participant_id="base",
        authenticated_participant=lambda _operation, _route: "base",
    )
    contributions = production_runtime_contributions(
        host=_Host(),
        root=root,
        preparation_owner=owner,
        technical_peer_material_provider=_peer,
    )(state)

    assert contributions.users == ()
    assert contributions.fragments == {}
    assert not root.exists()


def test_read_only_queries_do_not_create_credentials_or_preparation_files(tmp_path: Path):
    route = _route()
    state = _state(route)
    owner, _records_store, credentials, _store, _evidence = _owner(tmp_path, state, "base")
    renderer = _renderer(owner, credentials, "base")

    with pytest.raises(ValueError, match="durable participant snapshots"):
        owner.prepare("stage-1", "vless")
    assert owner.preparations_for_render(state) == ()
    assert renderer.render(state).users == ()
    assert not (tmp_path / "credentials").exists()
    assert not (tmp_path / "preparations").exists()


def test_preparation_is_idempotent_across_restart_and_accepts_prepared_config_identity(tmp_path: Path):
    route = _route()
    state = _state(route)
    owner, records, credentials, store, evidence = _owner(tmp_path, state, "base")
    _confirm_snapshots(records)
    first = owner.prepare("stage-1", "vless")
    evidence["current"] = _PREPARED

    restarted = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=lambda: copy.deepcopy(state),
        credentials=credentials,
        store=CascadePreparationStore(host=_Host(), root=tmp_path / "preparations"),
        participant_id="base",
        authenticated_participant=lambda _operation, _route: "base",
        evidence_provider=owner.evidence_provider,
    )
    assert restarted.prepare("stage-1", "vless") == first
    assert restarted.preparations_for_render(state) == (first,)
    assert store.load("stage-1", route.id, "base", "vless") == first
    assert len(list((tmp_path / "preparations").glob("*.json"))) == 1


def test_wrong_participant_protocol_plan_lease_and_engine_cannot_render_preparation(tmp_path: Path):
    route = _route()
    state = _state(route)
    owner, records, credentials, _store, evidence = _owner(tmp_path, state, "base")
    _confirm_snapshots(records)
    owner.prepare("stage-1", "vless")

    with pytest.raises(KeyError, match="unknown cascade preparation operation"):
        owner.prepare("missing-operation", "vless")
    evidence["authenticated"] = "other"
    assert owner.preparations_for_render(state) == ()
    evidence["authenticated"] = "base"
    evidence["engine"] = "9" * 64
    assert owner.preparations_for_render(state) == ()
    evidence["engine"] = _ENGINE
    evidence["current"] = "8" * 64
    assert owner.preparations_for_render(state) == ()
    evidence["current"] = _BASELINE
    with pytest.raises(ValueError, match="not selected"):
        owner.prepare("stage-1", "unsupported")

    invalid_state = copy.deepcopy(state)
    namespace = managed_nodes_from_extensions(invalid_state.feature_extensions)
    namespace.operations[0] = replace(
        namespace.operations[0], plan={"cascade_id": route.id, "cascade": route.to_document()}
    )
    store_managed_nodes(invalid_state.feature_extensions, namespace)
    invalid_owner, _records_store, _credentials, _store, _evidence = _owner(tmp_path / "invalid", invalid_state, "base")
    with pytest.raises(ValueError, match="digest"):
        invalid_owner.prepare("stage-1", "vless")

    wrong_role, _records_store, _credentials, _store, _evidence = _owner(tmp_path / "role", state, "unrelated")
    with pytest.raises(ValueError, match="not in the frozen route"):
        wrong_role.prepare("stage-1", "vless")

    conflict_route = _route(entry="base", exit="other-exit")
    conflict = _operation(conflict_route, "stage-2")
    current = managed_nodes_from_extensions(state.feature_extensions)
    current.operations.append(conflict)
    store_managed_nodes(state.feature_extensions, current)
    assert owner.preparations_for_render(state) == ()
    assert cascade_participants(current.operations[0]) == {"base", "exit"}


def test_missing_peer_material_never_promotes_syntax_to_business_rendering(tmp_path: Path):
    route = _route()
    state = _state(route, users=[User("business@example.test", "business-uuid")])
    owner, records, credentials, _store, _evidence = _owner(tmp_path, state, "base")
    _confirm_snapshots(records)
    preparation = owner.prepare("stage-1", "vless")
    transit = credentials.load(route.id).technical_subject("exit", "vless", "transit", "stage-1")
    invalid_peer = replace(_peer(state, preparation, transit), role="entry")
    with pytest.raises(ValueError, match="another preparation"):
        invalid_peer.validate_for(preparation, transit)

    contributions = _renderer(owner, credentials, "base", peer=False).render(state)

    assert contributions.users == ()
    assert contributions.fragments == {}
    assert state.users[0].uuid == "business-uuid"
    assert managed_nodes_from_extensions(state.feature_extensions).cascades == []


class _Runtime:
    def __init__(self, *, unknown=False, path_ok=True, rollback_ok=True):
        self.unknown = unknown
        self.path_ok = path_ok
        self.rollback_ok = rollback_ok
        self.applied = set()
        self.snapshots = []

    def capabilities(self, participant_id: str) -> dict[str, dict[str, bool]]:
        del participant_id
        return {name: {"client": True, "server": True, "probe": True} for name in ("vless", "anytls")}

    def ensure_snapshot(self, operation_id: str, participant_id: str, previous: CascadeDefinition | None) -> None:
        self.snapshots.append((operation_id, participant_id, previous))

    def participant_status(self, operation_id: str, participant_id: str) -> str:
        del operation_id
        if self.unknown:
            return "unknown"
        return "applied" if participant_id in self.applied else "not_applied"

    def apply_participant(self, operation_id: str, participant_id: str, definition: CascadeDefinition | None) -> None:
        del operation_id, definition
        self.applied.add(participant_id)

    def verify_path(self, operation_id: str, definition: CascadeDefinition) -> bool:
        del operation_id, definition
        return self.path_ok

    def commit_profiles(self, operation_id: str, definition: CascadeDefinition | None) -> None:
        del operation_id, definition
        raise AssertionError("technical preparation must not publish business profiles")

    def rollback_participant(self, operation_id: str, participant_id: str) -> bool:
        del operation_id
        if self.rollback_ok:
            self.applied.discard(participant_id)
        return self.rollback_ok


def _cascade_service(tmp_path: Path, runtime: _Runtime):
    route = _route()
    state = _state(route)
    state.feature_extensions["managed_nodes"] = ManagedNodesState(
        definitions=[
            NodeDefinition(
                "exit",
                "Exit",
                "203.0.113.9",
                "root",
                "dev",
                _REVISION,
                25555,
                [ProtocolAssignment("vless")],
                "managed-node/exit",
            ),
        ],
        operations=[_operation(route)],
    ).to_document()
    records = _records(state)
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "credentials")
    owner, _owner_records, _owner_credentials, preparation_store, _evidence = _owner(tmp_path, state, "base")
    evidence_provider = owner.evidence_provider
    assert evidence_provider is not None

    def require_snapshots(*args):
        assert len(runtime.snapshots) == 2
        return evidence_provider(*args)

    owner.evidence_provider = require_snapshots
    service = ManagedNodeCascadeService(
        records=records,
        runtime=runtime,
        credentials=credentials,
        preparation_owner=owner,
        operation_id_factory=lambda: "stage-1",
    )
    return service, records, credentials, preparation_store, runtime, route


def test_unknown_participant_result_retains_operation_seed_and_preparation(tmp_path: Path):
    service, records, credentials, store, runtime, route = _cascade_service(
        tmp_path,
        _Runtime(unknown=True),
    )

    result = service.save_cascade(route, confirmed=True)

    assert result.state == "recovery_required"
    assert [participant for _, participant, _ in runtime.snapshots] == ["base", "exit"]
    assert records.find_cascade(route.id) is None
    assert credentials.exists(route.id)
    assert store.load("stage-1", route.id, "base", "vless").plan_digest == result.desired_digest
    assert result.id == "stage-1"


def test_failed_rollback_retains_frozen_preparation_and_credentials(tmp_path: Path):
    service, records, credentials, store, runtime, route = _cascade_service(
        tmp_path,
        _Runtime(path_ok=False, rollback_ok=False),
    )

    result = service.save_cascade(route, confirmed=True)

    assert result.state == "recovery_required"
    assert records.find_cascade(route.id) is None
    assert credentials.exists(route.id)
    assert store.load("stage-1", route.id, "base", "vless").operation_id == result.id
    assert set(runtime.applied) == {"base", "exit"}


def test_cascade_lease_cannot_be_released_by_a_direct_success_update(tmp_path: Path):
    route = _route(entry="entry", exit="exit")
    state = _state(route)
    records = _records(state)

    with pytest.raises(ValueError, match="completed profile verification"):
        records.commit_cascade_operation("stage-1", route)
    records.begin_step("stage-1", "snapshot")
    records.complete_step("stage-1", "snapshot")
    records.begin_step("stage-1", "profiles")
    records.complete_step("stage-1", "profiles")
    current = records.find_operation("stage-1")
    assert current is not None
    with pytest.raises(ValueError, match="only through atomic cascade commit"):
        records.update_operation(replace(current, state="succeeded"))
    with pytest.raises(ValueError, match="leased by an active cascade"):
        records.begin_operation(Operation("apply-entry", "apply", "entry", "d" * 64, "pending"))


def test_active_cascade_lease_excludes_peer_applies_definitions_and_routes_atomically(tmp_path: Path):
    route = _route(entry="entry", exit="exit")
    state = _state(route)
    namespace = managed_nodes_from_extensions(state.feature_extensions)
    namespace = replace(
        namespace,
        definitions=[
            NodeDefinition(
                node_id, node_id, "203.0.113.10", "root", "dev", _REVISION, 25555, [], f"managed-node/{node_id}"
            )
            for node_id in ("entry", "exit")
        ],
    )
    store_managed_nodes(state.feature_extensions, namespace)
    records = _records(state)

    for participant in ("entry", "exit"):
        with pytest.raises(ValueError, match="leased by an active cascade"):
            records.begin_operation(Operation(f"apply-{participant}", "apply", participant, "d" * 64, "pending"))
        definition = next(item for item in namespace.definitions if item.id == participant)
        with pytest.raises(ValueError, match="leased by an active cascade"):
            records.put_definition(replace(definition, name="mutated"))
        with pytest.raises(ValueError, match="leased by an active cascade"):
            records.begin_protocol_apply(participant, ProtocolAssignment("vless"), f"protocol-{participant}")

    overlap = _operation(_route(entry="entry", exit="another"), "stage-2")
    with pytest.raises(ValueError, match="already leased"):
        records.begin_operation(overlap)
    with pytest.raises(ValueError, match="leased by an active cascade"):
        records.put_cascade(_route(entry="entry", exit="another"))
    assert records.find_operation("stage-1") == _operation(route)
    assert records.find_operation("stage-2") is None
    assert records.find_cascade(route.id) is None
