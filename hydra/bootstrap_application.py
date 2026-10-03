"""Shared service wiring called only by the production application root."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

from hydra.core import nft, singbox
from hydra.core.host import HOST
from hydra.core.state import save_state
from hydra.core.state_models import get_protocol
from hydra.services.admin_infrastructure import AdminInfrastructure
from hydra.services.certificate_audit import CertificateInspector
from hydra.services.certificates import CertificateProvisioner
from hydra.services.kernel import KernelService
from hydra.services.kernel_infrastructure import KernelInfrastructure
from hydra.services.maintenance import MaintenanceService
from hydra.services.sync_agent import run_sync
from hydra.services.sync_ports import default_sync_operations, subscription_certificate_renewal
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.orchestration_service import OrchestrationService


def production_orchestration(plugins: Any, apply_gate: ManagedNodeApplyGate) -> tuple[OrchestrationService, Any]:
    certificates = CertificateProvisioner(cast(Any, HOST))
    orchestration = OrchestrationService(
        plugins=plugins,
        singbox=singbox,
        nft=nft,
        host=HOST,
        save_state=save_state,
        get_protocol=get_protocol,
        certificates=certificates,
        traffic_daemon_service=Path("/etc/systemd/system/hydra-traffic-daemon.service"),
        apply_journal=Path("/var/log/hydra/apply.jsonl"),
        apply_lock_file=Path(os.environ.get("HYDRA_APPLY_LOCK_FILE", "/run/lock/hydra-apply.lock")),
        managed_node_apply_gate=apply_gate,
    )
    return orchestration, certificates


def production_admin_surfaces(protocols, traffic, orchestration, plugin_actions, plugin_queries, node_sync, calls):
    """Compose admin, maintenance and kernel adapters, including lazy renewal wiring."""
    maintenance = MaintenanceService(protocols, plugin_actions, plugin_queries, calls)
    kernel = KernelService(KernelInfrastructure(HOST), save_state=save_state)
    certificate_audit = CertificateInspector(cast(Any, HOST))
    admin: Any = None

    def renew_certificate(domain):
        return subscription_certificate_renewal(cast(Any, admin))(domain)

    admin = AdminInfrastructure(
        sync_operations=default_sync_operations(
            protocols=protocols,
            plugin_actions=plugin_actions,
            plugin_queries=plugin_queries,
            apply_config=orchestration.apply_config,
            check_traffic_limits=traffic.check_limits,
            inspect_certificates=certificate_audit.inspect,
            renew_subscription_certificate=renew_certificate,
            maintenance=maintenance,
            managed_node_sync=node_sync,
        ),
        sync_runner=run_sync,
    )
    return admin, maintenance, kernel, certificate_audit


__all__ = ["production_orchestration", "production_admin_surfaces"]
