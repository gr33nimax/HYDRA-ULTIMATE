"""Additional evidence-driven findings for the Hydracore Calls pipeline."""
from __future__ import annotations

from collections.abc import Mapping


def extended_native_findings(
    native: Mapping[str, object],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    counters = _combined_counters(native)
    if _sum(counters, "handshake_rejected", "handshake_timeout"):
        findings.append(_finding(
            "critical", "handshake_capacity_pressure",
            "The VPS rejected or timed out native worker handshakes.",
            "Correlate pending handshakes with CPU and UDP queues; then A/B the accept path and limit.",
        ))
    if _sum(counters, "worker_liveness_expired", "worker_reconnect"):
        findings.append(_finding(
            "warning", "worker_transport_instability",
            "Workers expired their liveness window or repeatedly reconnected.",
            "Split by tester/network and compare TURN RTT, heartbeat delivery, rebind and reconnect backoff.",
        ))
    outer_failures = _sum(
        counters,
        "outer_auth_failures",
        "outer_wrap_failures",
    )
    outer_packets = _sum(counters, "outer_packets_in", "outer_packets_out")
    outer_failure_ratio = outer_failures / max(1.0, outer_packets)
    if outer_failures >= 10 and (
        outer_failure_ratio >= 0.001 or outer_failures >= 1000
    ):
        findings.append(_finding(
            "critical", "outer_packet_authentication_failures",
            "The RTP-shaped ChaCha20-Poly1305 layer rejected or failed to wrap packets.",
            "Separate wrong-key/replay input from corruption and CPU/allocator failures before tuning KCP.",
        ))
    if _sum(counters, "relay_connect_failure"):
        findings.append(_finding(
            "warning", "relay_connect_failures",
            "The inner TCP/UDP relay could not open requested destinations.",
            "Separate DNS/destination failures from tunnel loss; they do not justify transport tuning.",
        ))
    if _gauge_peak(native, "network_loss_ratio") >= 0.05:
        findings.append(_finding(
            "warning", "client_network_loss",
            "At least one tester observed p95 packet loss of 5% or more.",
            "Compare the same workload across Wi-Fi/mobile networks and TURN choices before KCP changes.",
        ))
    if _gauge_peak(native, "kcp_rtt_ms") >= 300:
        findings.append(_finding(
            "warning", "high_kcp_rtt",
            "KCP p95 RTT reached 300 ms or more.",
            "Break RTT down by tester and worker, then compare region/TURN routing and queue occupancy.",
        ))
    efficiency = native.get("goodput_wire_efficiency_ratio")
    if type(efficiency) in {int, float} and 0 < float(efficiency) < 0.6:
        findings.append(_finding(
            "warning", "low_wire_efficiency",
            "Less than 60% of measured outer bytes became application goodput.",
            "Use outer payload/overhead and KCP retransmit bytes to locate the excess before changing MTU.",
        ))
    return findings


def _combined_counters(native: Mapping[str, object]) -> dict[str, float]:
    summaries = [_mapping(native.get("server"))]
    summaries.extend(
        _mapping(value) for value in _mapping(native.get("clients")).values()
    )
    counters: dict[str, float] = {}
    for summary in summaries:
        for key, value in _mapping(summary.get("counters")).items():
            counters[str(key)] = counters.get(str(key), 0.0) + _number(value)
    return counters


def _gauge_peak(native: Mapping[str, object], key: str) -> float:
    summaries = [_mapping(native.get("server"))]
    summaries.extend(
        _mapping(value) for value in _mapping(native.get("clients")).values()
    )
    return max(
        (
            _number(
                _mapping(_mapping(summary.get("gauges")).get(key)).get("p95"),
            )
            for summary in summaries
        ),
        default=0.0,
    )


def _sum(counters: Mapping[str, object], *fragments: str) -> float:
    return sum(
        _number(value)
        for key, value in counters.items()
        if any(fragment in str(key) for fragment in fragments)
    )


def _finding(severity: str, code: str, message: str, next_step: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message, "next_step": next_step}


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _number(value: object) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


__all__ = ["extended_native_findings"]
