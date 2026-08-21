"""Wire-efficiency aggregation for Calls telemetry reports."""
from __future__ import annotations

import math
from collections.abc import Mapping


def native_wire_breakdown(counters: Mapping[str, object]) -> dict[str, float | None]:
    """Return comparable outer-wire, QUIC and relay counters."""
    def number(key: str) -> float:
        try:
            value = float(counters.get(key))
            return value if math.isfinite(value) else 0.0
        except (TypeError, ValueError):
            return 0.0

    def combined(left: str, right: str) -> float:
        return number(left) + number(right)

    def optional(key: str) -> float | None:
        return round(number(key), 3) if key in counters else None

    return {
        "outer_bytes": round(combined("outer_bytes_in_total", "outer_bytes_out_total"), 3),
        "outer_payload_bytes": round(
            combined("outer_payload_bytes_in_total", "outer_payload_bytes_out_total"), 3,
        ),
        "outer_overhead_bytes": round(
            combined("outer_overhead_bytes_in_total", "outer_overhead_bytes_out_total"), 3,
        ),
        "quic_retransmit_bytes": round(number("quic_bytes_retrans_total"), 3),
        "quic_packets_lost": optional("quic_packets_lost_total"),
        "quic_datagrams_sent": optional("quic_datagrams_sent_total"),
        "quic_datagrams_dropped": optional("quic_datagrams_dropped_total"),
        "relay_goodput_bytes": round(number("relay_bytes_total"), 3),
    }


__all__ = ["native_wire_breakdown"]
