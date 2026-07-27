"""Production composition root for all executable adapters."""
from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from hydra.core import nft, singbox
from hydra.core.doctor import run_host_preflight
from hydra.core.host import HOST
from hydra.core.sni_router import audit_routes
from hydra.core.state import (
    load_state,
    migrate_persisted_state,
    restore_desired_state,
    save_state,
)
from hydra.core.state_models import get_protocol, validate_state
from hydra.core.upgrade import check_upgrade
from hydra.plugins.container import PluginContainer
from hydra.plugins.defaults import PluginFactory, default_plugins
from hydra.services.admin_infrastructure import AdminInfrastructure
from hydra.services.application import ApplicationService
from hydra.services.backups import BackupService, compose_backup_policy
from hydra.services.certificate_audit import CertificateInspector
from hydra.services.certificates import CertificateProvisioner
from hydra.services.configuration_plan import ConfigurationPlanner
from hydra.services.diagnostic_infrastructure import HOST_DIAGNOSTICS
from hydra.services.log_infrastructure import HostLogOperations
from hydra.services.orchestration_service import OrchestrationService
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_commands import PluginCommandService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.services.protocols import ProtocolService
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


def _disable_telemt_ios_fix() -> None:
    from hydra.plugins.telemt.telemt_ios_fix import disable_ios_fix

    disable_ios_fix()


def _disable_telemt_syn_limiter() -> None:
    from hydra.plugins.telemt.telemt_syn_limiter import disable_syn_limiter

    disable_syn_limiter()


def production_application(
    *,
    extra_plugin_factories: Iterable[PluginFactory] = (),
) -> ApplicationService:
    """Build a fresh, instance-scoped production application."""
    plugins = PluginContainer(
        default_plugins(
            notifier=notify_security_event,
            security_context=notification_fields,
            extra_factories=extra_plugin_factories,
        ),
        host=HOST,
        log_error=lambda message: singbox.log("ERROR", message),
    )
    certificates = CertificateProvisioner(HOST)
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
    )
    traffic = TrafficService(protocols)
    plugin_actions = PluginActionService(get_plugin=plugins.get)
    plugin_queries = PluginQueryService(get_plugin=plugins.get)
    certificate_audit = CertificateInspector(HOST)
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
            renew_subscription_certificate=lambda domain: (
                subscription_certificate_renewal(admin)(domain)
            ),
        ),
        sync_runner=run_sync,
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
            compose_backup_policy(plugins.backup_resources()),
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
        ),
        plugin_queries=plugin_queries,
        plugin_actions=plugin_actions,
        traffic=traffic,
        planner=ConfigurationPlanner(
            collect_fragments=plugins.collect_fragments,
            generate_config=singbox.generate_config,
            preflight_conflicts=singbox.preflight_conflicts,
            requirements=plugins.requirements,
            reconciliation_plan=protocols.reconciliation().plan,
            route_audit=audit_routes,
        ),
        uninstaller=UninstallService(
            plugin_inventory=plugins.all_plugins,
            cleanup_steps=(
                CleanupStep("telemt-ios", _disable_telemt_ios_fix),
                CleanupStep("telemt-syn", _disable_telemt_syn_limiter),
            ),
        ),
        certificates=certificate_audit,
    )


__all__ = ["production_application"]
