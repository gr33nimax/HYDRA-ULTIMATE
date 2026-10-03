"""Production composition root for all executable adapters."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, cast

from hydra.core import singbox, state as state_backend
from hydra.core.doctor import run_host_preflight
from hydra.core.host import HOST
from hydra.core.legacy_sidecars import purge_legacy_sidecars
from hydra.core.sni_router import audit_routes
from hydra.core.state import (
    load_state,
    migrate_persisted_state,
    restore_desired_state,
    save_state,
    update_state,
)
from hydra.core.state_models import validate_state
from hydra.core.upgrade import check_upgrade
from hydra.plugins.defaults import PluginFactory
from hydra.services.application import ApplicationService
from hydra.services.backups import BackupService, compose_backup_policy
from hydra.services.calls_composition import create_calls_runtimes, create_calls_service
from hydra.services.configuration_plan import ConfigurationPlanner
from hydra.services.diagnostic_infrastructure import HOST_DIAGNOSTICS
from hydra.services.log_infrastructure import HostLogOperations
from hydra.services.managed_nodes.agent import ManagedNodeAgent
from hydra.services.managed_nodes.apply import ManagedNodeApplyService
from hydra.services.managed_nodes.checks import ManagedNodeCheckService
from hydra.services.managed_nodes.client import client_from_credentials
from hydra.services.managed_nodes.cascade_runtime import CascadeRuntime
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes import cascade_leases, cascade_preparation
from hydra.services.managed_nodes.cascade_rendering import TechnicalPeerMaterialProvider
from hydra.services.managed_nodes.cascades import ManagedNodeCascadeService
from hydra.services.managed_nodes.apply_gate import AuthenticatedParticipant, ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant
from hydra.services.managed_nodes.cascade_runtime_service import ManagedNodeCascadeRuntime
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.observations import ManagedNodeObservationProvider, ManagedNodeObservationStore
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.probe_clients import (
    ManagedNodeProbeClient,
    ManagedNodeProbeIdentityStore,
    ManagedNodeProbeMaterialProvider,
)
from hydra.services.managed_nodes.profiles import ManagedNodeProfileBuilder
from hydra.services.managed_nodes.runtime import ManagedNodeRuntime
from hydra.services.managed_nodes.snapshots import ManagedNodeSnapshotStore
from hydra.services.managed_nodes.status import ManagedNodeStatusService
from hydra.services.managed_nodes.sync import ManagedNodeSyncService
from hydra.services.subscriptions.node_exports import ManagedNodeSubscriptionReader
from hydra.services.managed_nodes.identity import ManagementIdentity, load_management_identity
from hydra.services.managed_nodes.installation import resolve_managed_node_revision
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import OpenSshManagedNodeSSH
from hydra.services.managed_nodes.enrollment import remove_management_firewall
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_commands import PluginCommandService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.services.protocols import ProtocolService
from hydra.services.vless_cdn_install import VlessCdnLifecycleOperations
from hydra.services.sync_agent import log_event
from hydra.services.sync_cycle import sync_user_limits
from hydra.services.system_monitoring_infrastructure import HOST_MONITORING
from hydra.services.system import SystemService
from hydra.services.traffic import TrafficService
from hydra.services.uninstall import CleanupStep, UninstallService
from hydra.services.users import UserService
from hydra.bootstrap_application import production_admin_surfaces, production_orchestration
from hydra.bootstrap_managed_nodes import production_managed_node_runtime
from hydra.bootstrap_cascade import production_cascade_components
from hydra.bootstrap_managed_nodes import preparation_owner as _cascade_preparation_owner


def _require_cleanup_result(operation) -> None:
    ok, message = operation()
    if not ok:
        raise RuntimeError(message)


_MANAGED_NODE_REPOSITORY = "https://github.com/gr33nimax/HYDRA-ULTIMATE"


def production_managed_node_operations(
    *,
    records=None,
    credentials=None,
    sync_service=None,
    status_service=None,
    cascade_runtime: CascadeRuntime | None = None,
    profile_reader=None,
    preparation_owner: cascade_preparation.ManagedNodeCascadePreparationOwner | None = None,
    cascade_participant_owner: ManagedNodeCascadeParticipant | None = None,
) -> ManagedNodeOperationsService:
    """Compose the scoped install/remove/sync port from injected dependencies."""
    root = state_backend.STATE_DIR / "managed-nodes"
    if records is None:
        apply_gate = ManagedNodeApplyGate(
            state_reader=load_state,
            participant_id="base",
            lock_path=root / "apply-gate.lock",
        )
        node_records = ManagedNodeRecords(
            state_reader=load_state,
            state_updater=apply_gate.wrap_state_updater(update_state),
        )
    else:
        node_records = records
    credential_store = credentials or ManagementCredentialStore(host=HOST, root=root / "credentials")
    local_identity_path = Path("/etc/hydra/managed-node/identity.json")
    if cascade_runtime is not None and preparation_owner is None:
        raise ValueError("production cascade runtime requires an explicit technical preparation owner")
    cascade_credentials = CascadeCredentialStore(host=HOST, root=root / "cascade-credentials")
    return ManagedNodeOperationsService(
        records=node_records,
        ssh=OpenSshManagedNodeSSH(host=HOST, known_hosts_root=root / "known-hosts"),
        credentials=credential_store,
        revision_resolver=partial(resolve_managed_node_revision, HOST, repository=_MANAGED_NODE_REPOSITORY),
        operation_id_factory=lambda: secrets.token_hex(16),
        client_factory=lambda definition, files=None, certificate=None: client_from_credentials(
            credential_store,
            definition,
            files,
            certificate,
        ),
        sync_service=sync_service,
        status_service=status_service,
        cascade_service=ManagedNodeCascadeService(
            records=node_records,
            runtime=cascade_runtime,
            credentials=cascade_credentials,
            preparation_owner=preparation_owner,
        ),
        profile_reader=profile_reader,
        cascade_participant_owner=cascade_participant_owner,
        local_identity_reader=lambda: (
            load_management_identity(Path("/etc/hydra/managed-node"), host=HOST)
            if local_identity_path.exists() or local_identity_path.is_symlink()
            else None
        ),
    )


def production_managed_node_agent(identity: ManagementIdentity) -> ManagedNodeAgent:
    """Compose node apply, receipts, profile sync and isolated native probe support."""
    node_root = Path("/etc/hydra/managed-node")
    profile_store = ManagedNodeProfileStore(host=HOST, root=state_backend.STATE_DIR / "managed-node-profiles")
    probe_identity = ManagedNodeProbeIdentityStore(host=HOST, root=node_root, node_id=identity.node_id)
    probe_identity.ensure()
    application = production_application(managed_node_probe_identity=probe_identity)
    records = cast(Any, application.nodes)._records
    runtime = ManagedNodeRuntime(host=HOST, config_path=singbox.SINGBOX_CONFIG)
    builder = ManagedNodeProfileBuilder(protocols=application.protocols)
    snapshots = ManagedNodeSnapshotStore(host=HOST, root=state_backend.STATE_DIR / "managed-node-snapshots")
    applier = ManagedNodeApplyService(
        node_id=identity.node_id,
        records=records,
        state_reader=load_state,
        restore_state=restore_desired_state,
        reconcile_users=application.users.operations.reconcile_users,
        apply_config=application.apply_config,
        protocols=application.protocols,
        runtime=runtime,
        profile_builder=builder,
        profile_store=profile_store,
        snapshots=snapshots,
        lock_path=Path(f"/run/lock/hydra-managed-node-{identity.node_id}.lock"),
    )
    observations = ManagedNodeObservationProvider(
        node_id=identity.node_id,
        records=records,
        runtime=runtime,
        protocols=application.protocols,
        state_reader=load_state,
        state_updater=update_state,
        mutation_lock=applier.accounting_lock,
    )
    probes = ManagedNodeProbeMaterialProvider(
        node_id=identity.node_id,
        identity=probe_identity,
        protocols=application.protocols,
    )

    def probe_materials():
        sample, state = observations.read_with_state()
        if sample.receipt is None:
            raise RuntimeError("committed apply and active runtime are not confirmed")
        return probes.materials(state, sample.receipt)

    applier.recover_pending()
    return ManagedNodeAgent(
        node_id=identity.node_id,
        state_provider=observations.read,
        sync_sample_provider=observations.sync_sample,
        submit_provider=applier.submit,
        operation_provider=applier.operation,
        profiles_provider=applier.profiles,
        probe_materials_provider=probe_materials,
        cascade_participant=cast(Any, application.nodes).management_agent_cascade_owner(),
    )


def _cleanup_managed_node_probe_identity() -> None:
    root = Path("/etc/hydra/managed-node")
    path = root / "probe-identity.json"
    if root.is_symlink() or path.is_symlink():
        raise ValueError("managed-node probe identity path is unsafe")
    if not path.exists():
        return
    ManagedNodeProbeIdentityStore(host=HOST, root=root, node_id="cleanup").cleanup()


def _cleanup_managed_node_firewall() -> None:
    root = Path("/etc/hydra/managed-node")
    config = root / "identity.json"
    if config.is_symlink():
        raise ValueError("managed-node identity path is unsafe")
    if not config.exists():
        return
    identity = load_management_identity(root, host=HOST)
    remove_management_firewall(
        host=HOST,
        node_id=identity.node_id,
        allowed_source_ips=identity.allowed_source_ips,
    )


def _managed_node_services(
    protocols,
    traffic,
    *,
    preparation_owner=None,
    cascade_runtime=None,
    cascade_participant_owner=None,
    records=None,
):
    node_root = state_backend.STATE_DIR / "managed-nodes"
    records = records or ManagedNodeRecords(state_reader=load_state, state_updater=update_state)
    credentials = ManagementCredentialStore(host=HOST, root=node_root / "credentials")
    client_factory = lambda definition: client_from_credentials(credentials, definition)
    profile_store = ManagedNodeProfileStore(host=HOST, root=state_backend.STATE_DIR / "managed-node-profiles")
    observations = ManagedNodeObservationStore(host=HOST, root=state_backend.STATE_DIR / "managed-node-observations")
    checks = ManagedNodeCheckService(
        records=records,
        state_reader=load_state,
        client_factory=client_factory,
        profile_store=profile_store,
        observations=observations,
        probe_client=ManagedNodeProbeClient(host=HOST),
    )

    def local_user_sync():
        state = load_state()
        return sync_user_limits(
            state,
            enabled=bool(state.install.get("sync_limits_enabled", True)),
            now=datetime.now(timezone.utc),
            check_traffic_limits=traffic.check_limits,
            notify_user_block=protocols.notify_user_block,
            update_state=update_state,
            log=log_event,
        )

    sync_service = ManagedNodeSyncService(
        records=records,
        state_reader=load_state,
        state_updater=update_state,
        client_factory=client_factory,
        profile_store=profile_store,
        observations=observations,
        checks=checks,
        local_user_sync=local_user_sync,
    )
    status = ManagedNodeStatusService(
        records=records,
        observations=observations,
        state_reader=load_state,
    )
    profiles = ManagedNodeSubscriptionReader(profile_store=profile_store)
    operations = production_managed_node_operations(
        records=records,
        credentials=credentials,
        sync_service=sync_service,
        status_service=status,
        profile_reader=profiles.profiles_for_user,
        preparation_owner=preparation_owner,
        cascade_runtime=cascade_runtime,
        cascade_participant_owner=cascade_participant_owner,
    )
    return operations, sync_service


def production_application(
    *,
    extra_plugin_factories: Iterable[PluginFactory] = (),
    managed_node_probe_identity: ManagedNodeProbeIdentityStore | None = None,
    cascade_preparation_evidence_provider: cascade_preparation.EvidenceProvider | None = None,
    cascade_technical_peer_material_provider: TechnicalPeerMaterialProvider | None = None,
    cascade_apply_authenticated_participant_provider: AuthenticatedParticipant | None = None,
) -> ApplicationService:
    """Build a fresh, instance-scoped production application."""
    calls_creator_runtime, calls_runtime = create_calls_runtimes(HOST)
    node_root = state_backend.STATE_DIR / "managed-nodes"
    participant_id = managed_node_probe_identity.node_id if managed_node_probe_identity is not None else "base"
    authenticated_owner = cascade_apply_authenticated_participant_provider or (
        lambda operation: participant_id if participant_id in cascade_leases.cascade_participants(operation) else None
    )
    plugins, records, preparation_owner, apply_gate, participant_store = production_managed_node_runtime(
        host=HOST,
        root=node_root,
        state_reader=load_state,
        state_updater=update_state,
        participant_id=participant_id,
        evidence_provider=cascade_preparation_evidence_provider,
        authenticated_participant=authenticated_owner,
        technical_peer_material_provider=cascade_technical_peer_material_provider,
        calls_runtime=calls_runtime,
        extra_plugin_factories=extra_plugin_factories,
        probe_identity=managed_node_probe_identity,
        log_error=lambda message: singbox.log("ERROR", message),
    )
    orchestration, certificates = production_orchestration(plugins, apply_gate)
    protocols = ProtocolService(
        orchestration,
        plugins,
        state_reader=load_state,
        lifecycle_overrides={
            "vless_cdn": VlessCdnLifecycleOperations(orchestration),
        },
    )
    traffic = TrafficService(protocols)
    participant_owner, cascade_runtime = production_cascade_components(
        host=HOST,
        root=node_root,
        participant_id=participant_id,
        records=records,
        gate=apply_gate,
        preparation=preparation_owner,
        participant_store=participant_store,
        orchestration=orchestration,
        protocols=protocols,
    )
    nodes, node_sync = _managed_node_services(
        protocols,
        traffic,
        preparation_owner=preparation_owner,
        cascade_runtime=cascade_runtime,
        cascade_participant_owner=participant_owner,
        records=records,
    )
    plugin_actions = PluginActionService(get_plugin=plugins.get)
    plugin_queries = PluginQueryService(get_plugin=plugins.get)
    calls = create_calls_service(
        HOST,
        calls_creator_runtime,
        calls_runtime,
        protocols,
        orchestration,
        save_state,
    )
    admin, maintenance, kernel, certificate_audit = production_admin_surfaces(
        protocols, traffic, orchestration, plugin_actions, plugin_queries, node_sync, calls
    )

    return ApplicationService(
        users=UserService(orchestration),
        protocols=protocols,
        apply_config=orchestration.apply_config,
        last_apply_error=orchestration.last_apply_error,
        plugin_statuses=protocols.statuses,
        reconcile_runtime=orchestration.reconcile_traffic_daemon,
        apply_journal=lambda: orchestration.apply_journal,
        admin=admin,
        backups=BackupService(
            compose_backup_policy(
                plugins.backup_resources(),
            ),
        ),
        logs=HostLogOperations(
            run_command=admin.run_command,
            popen_command=admin.popen_command,
            unit_active=admin.unit_active,
            unit_known=admin.unit_known,
        ),
        diagnostics=HOST_DIAGNOSTICS,
        monitoring=HOST_MONITORING,
        system=SystemService(
            validate_state=validate_state,
            doctor_check=run_host_preflight,
            upgrade_readiness=check_upgrade,
            migrate_persisted_state=migrate_persisted_state,
            purge_sidecars=lambda: purge_legacy_sidecars(HOST),
        ),
        plugin_commands=PluginCommandService(
            get_plugin=plugins.get,
            apply_config=orchestration.apply_config,
            save_state=save_state,
            restore_state=restore_desired_state,
            prepare_apply=ProtocolSetupService(
                certificates,
                plugins.get,
            ).prepare_enable,
            last_apply_error=orchestration.last_apply_error,
            set_apply_error=orchestration._set_apply_error,
        ),
        plugin_queries=plugin_queries,
        plugin_actions=plugin_actions,
        traffic=traffic,
        planner=ConfigurationPlanner(
            collect_fragments=plugins.collect_fragments,
            generate_config=cast(Any, singbox.generate_config),
            preflight_conflicts=singbox.preflight_conflicts,
            requirements=plugins.requirements,
            reconciliation_plan=protocols.reconciliation().plan,
            route_audit=audit_routes,
        ),
        uninstaller=UninstallService(
            plugin_inventory=plugins.all_plugins,
            cleanup_steps=(
                CleanupStep(
                    "calls-creator",
                    lambda: _require_cleanup_result(
                        calls_creator_runtime.uninstall_creator_pool,
                    ),
                ),
                CleanupStep("managed-node-firewall", _cleanup_managed_node_firewall),
                CleanupStep("managed-node-probe-identity", _cleanup_managed_node_probe_identity),
            ),
        ),
        certificates=certificate_audit,
        calls=calls,
        maintenance=maintenance,
        kernel=kernel,
        nodes=nodes,
    )


__all__ = [
    "production_application",
    "production_managed_node_agent",
    "production_managed_node_operations",
]
