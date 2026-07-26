"""Compatibility bridge from legacy diagnostic calls to the host adapter.

The neutral port never imports this module.  That keeps dependency direction
strictly ``compatibility -> infrastructure -> port`` and avoids an SCC.
"""
from __future__ import annotations

from typing import Any

from hydra.services.diagnostic_infrastructure import (
    HOST_DIAGNOSTICS,
    IP_VERSION_SELECTOR,
    address_family,
    legacy_dependency,
    original_getaddrinfo,
)
from hydra.services.diagnostics import (
    DiagnosticOperations,
    active_diagnostic_operations,
)


def current_diagnostic_operations() -> DiagnosticOperations:
    """Use an explicitly scoped adapter, falling back only for legacy callers."""

    return active_diagnostic_operations() or HOST_DIAGNOSTICS


def operations_from_application(application: object) -> DiagnosticOperations:
    """Resolve an explicitly configured application port without Mock leakage."""

    namespace = getattr(application, "__dict__", {})
    configured = namespace.get("diagnostics") if isinstance(namespace, dict) else None
    return configured or current_diagnostic_operations()


def selector_state() -> object:
    """Return the shared per-thread address-family selector."""

    return IP_VERSION_SELECTOR


def compatibility_dependency(name: str) -> Any:
    """Expose historical monkeypatch targets owned by infrastructure."""

    return legacy_dependency(name)


__all__ = [
    "address_family",
    "compatibility_dependency",
    "current_diagnostic_operations",
    "operations_from_application",
    "original_getaddrinfo",
    "selector_state",
]
