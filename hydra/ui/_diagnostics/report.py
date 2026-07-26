"""Read-only HYDRA runtime report composition."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui._diagnostics.report_sections import build_report


def run_diagnostics_report(app: ApplicationService) -> str:
    """Collect a live report through explicit application query ports."""
    monitoring = monitoring_from_application(app)
    return build_report(
        app,
        checked_at=monitoring.local_time("%Y-%m-%d %H:%M:%S"),
        windows=monitoring.is_windows(),
    )


__all__ = ["run_diagnostics_report"]
