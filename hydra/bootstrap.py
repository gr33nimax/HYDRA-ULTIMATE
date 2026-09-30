"""Production composition root for all executable adapters."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from hydra.core import nft, singbox, state as state_backend
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
from hydra.core.state_models import get_protocol, validate_state
from hydra.core.state_nodes import NodeConfig
from hydra.core.upgrade import check_upgrade
from hydra.plugins.container import PluginContainer
from hydra.plugins.defaults import PluginFactory, default_plugins
from hydra.services.admin_infrastructure import AdminInfrastructure
from hydra.services.application import ApplicationService
from hydra.services.backups import BackupService, compose_backup_policy
from hydra.services.certificate_audit import CertificateInspector
from hydra.services.certificates import CertificateProvisioner
from hydra.services.calls import CallsService
from hydra.services.calls_health import CallsProbeStore
from hydra.services.calls_infrastructure import (
    CALLS_CREATOR_UNIT,
    CALLS_POOL_DIR,
    CALLS_POOL_STATE,
    CALLS_PROBE_STATE,
    CallsInfrastructure,
)
from hydra.services.creator_sessions import CreatorSessionManager
from hydra.services.vk_turn_probe import VkTurnProbe
from hydra.services.creator_lock_infrastructure import CreatorFileLock
from hydra.services.headless_creator_infrastructure import HeadlessCreatorInfrastructure
from hydra.services.configuration_plan import ConfigurationPlanner
from hydra.services.diagnostic_infrastructure import HOST_DIAGNOSTICS
from hydra.services.log_infrastructure import HostLogOperations
from hydra.services.maintenance import MaintenanceService
from hydra.services.nodes.bootstrap import NodeBootstrap
from hydra.services.nodes.control_client import NodeControlClient
from hydra.services.nodes.credentials import cleanup_node_credentials
from hydra.services.nodes.installer import uninstall_node
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.kernel import KernelService
from hydra.services.kernel_infrastructure import KernelInfrastructure
from hydra.services.orchestration_service import OrchestrationService
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_commands import PluginCommandService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.services.protocols import ProtocolService
from hydra.services.vless_cdn_install import VlessCdnLifecycleOperations
from hydra.services.security_intel import notification_fields
from hydra.services.security_notifications import notify_security_event
from hydra.services.sync_agent import run_sync
from hydra.services.sync_ports import (
    default_sync_operations,
    subscription_certificate_renewal,
)
from hydra.services.system_monitoring_infrastructure import HOST_MONITORING
from hydra.services.system import SystemService
from hydra.services.traffic import TrafficService
from hydra.services.uninstall import CleanupStep, UninstallService
from hydra.services.users import UserService

if TYPE_CHECKING:
    from hydra.services.nodes.reconcile import NodeReconciler


def _require_cleanup_result(operation) -> None:
    ok, message = operation()
    if not ok:
        raise RuntimeError(message)


def _creator_runtimes() -> tuple[HeadlessCreatorInfrastructure, CallsInfrastructure]:
    calls_provider = HeadlessCreatorInfrastructure(
        HOST,
        pool_dir=CALLS_POOL_DIR,
        pool_state_file=CALLS_POOL_STATE,
        creator_unit=CALLS_CREATOR_UNIT,
        managed_consumer="calls",
        managed_unit_prefix="hydra-headless-creator-vk-calls",
    )
    runtime = CallsInfrastructure(
        HOST,
        pool_source=calls_provider,
    )
    return calls_provider, runtime


def production_node_cookie_import(cookies: object) -> None:
    """Write only the node's local VK credentials; never create a call pool."""
    provider, _ = _creator_runtimes()
    provider.import_vk_cookie_document(cookies)


def _creator_services(
    calls_creator_runtime,
    calls_runtime,
    protocols,
    orchestration,
):
    calls_creator_sessions = CreatorSessionManager({"vk": calls_creator_runtime})
    calls = CallsService(
        runtime=calls_runtime,
        creator=calls_creator_sessions,
        protocols=protocols,
        save_state=save_state,
        apply_config=orchestration.apply_config,
        operation_lock=CreatorFileLock(
            HOST,
            Path(
                os.environ.get(
                    "HYDRA_CALLS_LOCK_FILE",
                    "/run/lock/hydra-calls.lock",
                )
            ),
        ),
        last_apply_error=orchestration.last_apply_error,
        probe_store=CallsProbeStore(HOST, CALLS_PROBE_STATE),
        turn_probe=VkTurnProbe(),
    )
    return calls


def _production_node_client(node: NodeConfig, bootstrap: NodeBootstrap) -> NodeControlClient:
    credentials = bootstrap.load_control_credentials(node.id, address=node.address)
    expected = node.control_fingerprint.replace(":", "").casefold()
    if expected and expected != credentials.node_fingerprint.casefold():
        raise RuntimeError("node certificate fingerprint does not match its configuration")
    return NodeControlClient(
        host=node.address,
        port=node.control_port,
        node_id=node.id,
        ca_file=credentials.node_certificate,
        certificate=credentials.client_certificate,
        private_key=credentials.client_private_key,
        server_fingerprint=expected or credentials.node_fingerprint,
    )


def _import_node_cookies(node: NodeConfig, source: str, bootstrap: NodeBootstrap) -> None:
    from hydra.services.nodes.cookies import import_node_vk_cookies

    import_node_vk_cookies(node, source, host=HOST, known_hosts_root=bootstrap.known_hosts_root)


def _production_node_manager() -> NodeManager:
    script = (Path(__file__).resolve().parents[1] / "bootstrap.sh").read_text(encoding="utf-8")
    bootstrap = NodeBootstrap(host=HOST, script=script)

    def uninstall_remote(node: NodeConfig) -> None:
        uninstall_node(
            host=HOST,
            known_hosts_root=bootstrap.known_hosts_root,
            node_id=node.id,
            address=node.address,
            ssh_port=node.ssh_port,
        )

    def forget_credentials(node_id: str) -> None:
        cleanup_node_credentials(
            host=HOST,
            credentials_root=bootstrap.credentials_root,
            known_hosts_root=bootstrap.known_hosts_root,
            node_id=node_id,
            forget_host_key=True,
        )

    return NodeManager(
        state_reader=load_state,
        state_updater=update_state,
        client_for=lambda node: _production_node_client(node, bootstrap),
        snapshot_store=NodeSnapshotStore(
            host=HOST,
            root=state_backend.STATE_DIR / "node-exports",
        ),
        bootstrap=bootstrap,
        uninstall_remote=uninstall_remote,
        forget_node_credentials=forget_credentials,
        import_remote_cookies=lambda node, source: _import_node_cookies(node, source, bootstrap),
    )


def production_application(
    *,
    extra_plugin_factories: Iterable[PluginFactory] = (),
) -> ApplicationService:
    """Build a fresh, instance-scoped production application."""
    calls_creator_runtime, calls_runtime = _creator_runtimes()
    plugins = PluginContainer(
        default_plugins(
            notifier=notify_security_event,
            security_context=notification_fields,
            extra_factories=extra_plugin_factories,
            call_config_source=calls_runtime,
        ),
        host=HOST,
        log_error=lambda message: singbox.log("ERROR", message),
    )
    certificates = CertificateProvisioner(cast(Any, HOST))
    orchestration = OrchestrationService(
        plugins=plugins,
        singbox=singbox,
        nft=nft,
        host=HOST,
        save_state=save_state,
        get_protocol=get_protocol,
        certificates=certificates,
        traffic_daemon_service=Path(
            "/etc/systemd/system/hydra-traffic-daemon.service",
        ),
        apply_journal=Path("/var/log/hydra/apply.jsonl"),
        apply_lock_file=Path(
            os.environ.get(
                "HYDRA_APPLY_LOCK_FILE",
                "/run/lock/hydra-apply.lock",
            ),
        ),
    )
    protocols = ProtocolService(
        orchestration,
        plugins,
        state_reader=load_state,
        lifecycle_overrides={
            "vless_cdn": VlessCdnLifecycleOperations(orchestration),
        },
    )
    node_manager = _production_node_manager()
    traffic = TrafficService(protocols, after_user_reset=node_manager.reconcile_all)
    plugin_actions = PluginActionService(get_plugin=plugins.get)
    plugin_queries = PluginQueryService(get_plugin=plugins.get)
    calls = _creator_services(
        calls_creator_runtime,
        calls_runtime,
        protocols,
        orchestration,
    )
    maintenance = MaintenanceService(
        protocols=protocols,
        plugin_actions=plugin_actions,
        plugin_queries=plugin_queries,
        calls=calls,
    )
    kernel = KernelService(
        KernelInfrastructure(HOST),
        save_state=save_state,
    )
    certificate_audit = CertificateInspector(cast(Any, HOST))
    admin = AdminInfrastructure(
        sync_operations=default_sync_operations(
            protocols=protocols,
            plugin_actions=plugin_actions,
            plugin_queries=plugin_queries,
            apply_config=orchestration.apply_config,
            check_traffic_limits=traffic.check_limits,
            inspect_certificates=certificate_audit.inspect,
            # Resolved on call: the renewal needs the admin adapter being
            # assembled by this very statement.
            renew_subscription_certificate=lambda domain: subscription_certificate_renewal(admin)(domain),
            maintenance=maintenance,
            collect_node_traffic=node_manager.collect_traffic,
            reconcile_nodes=node_manager.reconcile_all,
        ),
        sync_runner=run_sync,
    )

    return ApplicationService(
        users=UserService(orchestration, after_node_change=node_manager.reconcile_all),
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
            ),
        ),
        certificates=certificate_audit,
        calls=calls,
        maintenance=maintenance,
        kernel=kernel,
        nodes=node_manager,
    )


def production_node_reconciler(node_id: str) -> NodeReconciler:
    """Compose the node control operations at the production root."""
    from hydra.services.nodes.reconcile import NodeReconciler as Reconciler
    from hydra.services.nodes.upgrade import NodeUpgradeScheduler

    return Reconciler(
        node_id,
        production_application(),
        state_reader=load_state,
        upgrade_scheduler=NodeUpgradeScheduler(HOST).schedule,
    )


def production_node_uninstall() -> dict[str, object]:
    """Remove this node through its freshly composed application services."""
    result = production_application().uninstaller.uninstall(
        load_state(),
        confirmed=True,
        keep_data=False,
    )
    ok = result.get("ok") if isinstance(result, dict) else None
    if type(ok) is not bool or not ok:
        raise RuntimeError("node uninstall did not complete successfully")
    return result


__all__ = [
    "production_application", "production_node_reconciler", "production_node_uninstall",
    "production_node_cookie_import",
]
