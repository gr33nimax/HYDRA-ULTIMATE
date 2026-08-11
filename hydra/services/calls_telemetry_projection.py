"""Small operator-facing projections of Calls telemetry reports and storage."""
from __future__ import annotations

from collections.abc import Mapping

from hydra.services.calls_telemetry_analysis_common import _integer


def report_projection(
    report: Mapping[str, object],
    *,
    recent_records: int,
) -> dict[str, object]:
    return {
        "window": report.get("window", {}),
        "calls": report.get("calls", {}),
        "testers": report.get("testers", []),
        "native": report.get("native", {}),
        "resources": report.get("resources", {}),
        "findings": report.get("findings", []),
        "recent_records_analyzed": recent_records,
    }


def storage_projection(session: Mapping[str, object]) -> dict[str, object]:
    data_bytes = _integer(session.get("data_bytes"))
    raw_data_bytes = _integer(session.get("raw_data_bytes")) or data_bytes
    return {
        "data_bytes": data_bytes,
        "raw_data_bytes": raw_data_bytes,
        "compression_ratio": (
            round(data_bytes / raw_data_bytes, 6) if raw_data_bytes else 1.0
        ),
        "timeline_segments": _integer(session.get("timeline_segments")),
        "max_data_bytes": _integer(session.get("max_data_bytes")),
    }


__all__ = ["report_projection", "storage_projection"]
