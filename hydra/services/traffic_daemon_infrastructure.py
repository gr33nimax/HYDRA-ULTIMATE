"""Host adapters used by the traffic-daemon entry point."""
from __future__ import annotations

from typing import Any

from hydra.services.traffic_attribution import (
    TrafficEvidence,
    evidence_from_journal,
)


JOURNAL_COMMAND = (
    "journalctl",
    "-u",
    "sing-box",
    "-n",
    "1000",
    "--no-pager",
)


def collect_traffic_evidence(host: Any) -> TrafficEvidence:
    """Read Sing-box once and build every protocol attribution index."""
    try:
        result = host.run(
            list(JOURNAL_COMMAND),
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception:
        return evidence_from_journal(())
    if result.returncode != 0:
        return evidence_from_journal(())
    return evidence_from_journal(result.stdout.splitlines())


__all__ = ["JOURNAL_COMMAND", "collect_traffic_evidence"]
