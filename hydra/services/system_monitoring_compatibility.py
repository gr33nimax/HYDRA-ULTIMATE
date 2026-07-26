"""Compatibility bridge for standalone system-monitor helpers.

Dependency direction stays ``compatibility -> infrastructure -> port``.
"""
from __future__ import annotations

from hydra.services.system_monitoring import SystemMonitoring
from hydra.services.system_monitoring_infrastructure import HOST_MONITORING


def legacy_system_monitoring() -> SystemMonitoring:
    """Return the local adapter for backward-compatible standalone helpers."""

    return HOST_MONITORING


def monitoring_from_application(application: object) -> SystemMonitoring:
    """Resolve an explicitly configured application port without Mock leakage."""

    namespace = getattr(application, "__dict__", {})
    configured = namespace.get("monitoring") if isinstance(namespace, dict) else None
    return configured or HOST_MONITORING
