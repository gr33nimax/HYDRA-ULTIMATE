"""Application boundary for operator-controlled Hydra VK Tunnel telemetry."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterator
from typing import Protocol, Sequence

from hydra import __version__
from hydra.contracts.calls_configuration import (
    CALL_MODE_VK_PARASITE,
    CALL_COUNT,
    DEFAULT_WORKERS,
    peer_read_queue_packets,
)
from hydra.core.state_models import AppState


DEFAULT_SAMPLE_INTERVAL_SECONDS = 2
DEFAULT_MAX_DATA_MIB = 2048
MIN_SAMPLE_INTERVAL_SECONDS = 2
MAX_SAMPLE_INTERVAL_SECONDS = 300
MIN_MAX_DATA_MIB = 16
MAX_MAX_DATA_MIB = 65536
MAX_TESTERS = 20


class CallsTelemetryRuntime(Protocol):
    """Protected local storage and host sampling used by the application."""

    def start(
        self,
        tester_emails: Sequence[str],
        *,
        sample_interval_seconds: int,
        max_data_bytes: int,
        metadata: dict[str, object],
    ) -> dict[str, object]: ...

    def status(self) -> dict[str, object]: ...

    def report(self, session_id: str = "") -> dict[str, object]: ...

    def tail(
        self,
        session_id: str = "",
        *,
        limit: int = 50,
    ) -> dict[str, object]: ...

    def follow(
        self,
        session_id: str = "",
        *,
        limit: int = 20,
    ) -> Iterator[dict[str, object]]: ...

    def mark(self, label: str) -> dict[str, object]: ...

    def export(self, session_id: str = "", output: str = "") -> dict[str, object]: ...

    def stop(self) -> dict[str, object]: ...


class CallsTelemetryOperations(Protocol):
    def start(
        self,
        state: AppState,
        tester_emails: Sequence[str],
        *,
        sample_interval_seconds: int = DEFAULT_SAMPLE_INTERVAL_SECONDS,
        max_data_mib: int = DEFAULT_MAX_DATA_MIB,
    ) -> dict[str, object]: ...

    def status(self) -> dict[str, object]: ...

    def report(self, session_id: str = "") -> dict[str, object]: ...

    def tail(
        self,
        session_id: str = "",
        *,
        limit: int = 50,
    ) -> dict[str, object]: ...

    def follow(
        self,
        session_id: str = "",
        *,
        limit: int = 20,
    ) -> Iterator[dict[str, object]]: ...

    def mark(self, label: str) -> dict[str, object]: ...

    def export(self, session_id: str = "", output: str = "") -> dict[str, object]: ...

    def stop(self) -> dict[str, object]: ...


@dataclass(frozen=True)
class CallsTelemetryService:
    """Validate an experiment before delegating host-local observations."""

    runtime: CallsTelemetryRuntime

    def start(
        self,
        state: AppState,
        tester_emails: Sequence[str],
        *,
        sample_interval_seconds: int = DEFAULT_SAMPLE_INTERVAL_SECONDS,
        max_data_mib: int = DEFAULT_MAX_DATA_MIB,
    ) -> dict[str, object]:
        calls = state.protocols.get("calls")
        if calls is None or not calls.enabled:
            raise ValueError("Hydra VK Tunnel must be enabled before telemetry starts")
        if not state.network.clash_api_enabled:
            raise ValueError("Clash API must be enabled for Calls telemetry")

        if type(sample_interval_seconds) is not int or not (
            MIN_SAMPLE_INTERVAL_SECONDS
            <= sample_interval_seconds
            <= MAX_SAMPLE_INTERVAL_SECONDS
        ):
            raise ValueError(
                "sample interval must be an integer between "
                f"{MIN_SAMPLE_INTERVAL_SECONDS} and "
                f"{MAX_SAMPLE_INTERVAL_SECONDS} seconds",
            )
        if type(max_data_mib) is not int or not (
            MIN_MAX_DATA_MIB <= max_data_mib <= MAX_MAX_DATA_MIB
        ):
            raise ValueError(
                "telemetry max data size must be an integer between "
                f"{MIN_MAX_DATA_MIB} and {MAX_MAX_DATA_MIB} MiB",
            )

        users_by_email = {user.email.casefold(): user.email for user in state.users}
        testers: list[str] = []
        seen: set[str] = set()
        for raw_email in tester_emails:
            email = str(raw_email).strip()
            key = email.casefold()
            if not email or key in seen:
                raise ValueError("tester emails must be non-empty and unique")
            canonical = users_by_email.get(key)
            if canonical is None:
                raise ValueError(f"unknown tester: {email}")
            seen.add(key)
            testers.append(canonical)
        if not 1 <= len(testers) <= MAX_TESTERS:
            raise ValueError(f"select between 1 and {MAX_TESTERS} testers")

        config = calls.config
        metadata: dict[str, object] = {
            "hydra_version": __version__,
            "state_schema": state.version,
            "kernel_provider": state.kernel.provider,
            "calls": {
                "mode": CALL_MODE_VK_PARASITE,
                "transport": "four_lane_kcp_v9",
                "lane_count": _safe_int(config.get("workers", DEFAULT_WORKERS)),
                "room_count": CALL_COUNT,
                "workers": _safe_int(config.get("workers", DEFAULT_WORKERS)),
                "listen_port": _safe_int(config.get("listen_port", 0)),
                "max_sessions": _safe_int(config.get("max_sessions", 128)),
                "max_sessions_per_user": _safe_int(
                    config.get("max_sessions_per_user", 1),
                ),
                "max_workers_per_session": _safe_int(
                    _safe_int(config.get("workers", DEFAULT_WORKERS)),
                ),
                "max_pending_handshakes": _safe_int(
                    config.get("max_pending_handshakes", 256),
                ),
                "handshake_timeout": str(config.get("handshake_timeout", "10s")),
                "session_idle_timeout": str(
                    config.get("session_idle_timeout", "5m"),
                ),
                "udp_receive_buffer_bytes": _safe_int(
                    config.get("udp_receive_buffer_bytes", 4 * 1024 * 1024),
                ),
                "udp_send_buffer_bytes": _safe_int(
                    config.get("udp_send_buffer_bytes", 4 * 1024 * 1024),
                ),
                "ingress_workers": _safe_int(config.get("ingress_workers", 0)),
                "ingress_queue_packets": _safe_int(
                    config.get("ingress_queue_packets", 4096),
                ),
                "peer_read_queue_packets": peer_read_queue_packets(config),
            },
        }
        return self.runtime.start(
            testers,
            sample_interval_seconds=sample_interval_seconds,
            max_data_bytes=max_data_mib * 1024 * 1024,
            metadata=metadata,
        )

    def status(self) -> dict[str, object]:
        return self.runtime.status()

    def report(self, session_id: str = "") -> dict[str, object]:
        return self.runtime.report(session_id)

    def tail(
        self,
        session_id: str = "",
        *,
        limit: int = 50,
    ) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("telemetry tail limit must be between 1 and 1000")
        return self.runtime.tail(session_id, limit=limit)

    def follow(
        self,
        session_id: str = "",
        *,
        limit: int = 20,
    ) -> Iterator[dict[str, object]]:
        if type(limit) is not int or not 0 <= limit <= 1000:
            raise ValueError("telemetry follow limit must be between 0 and 1000")
        return self.runtime.follow(session_id, limit=limit)

    def mark(self, label: str) -> dict[str, object]:
        return self.runtime.mark(label)

    def export(self, session_id: str = "", output: str = "") -> dict[str, object]:
        return self.runtime.export(session_id, output)

    def stop(self) -> dict[str, object]:
        return self.runtime.stop()


class UnavailableCallsTelemetryOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Calls telemetry operation is not configured: {name}")


def _safe_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "CallsTelemetryOperations",
    "CallsTelemetryRuntime",
    "CallsTelemetryService",
    "DEFAULT_MAX_DATA_MIB",
    "DEFAULT_SAMPLE_INTERVAL_SECONDS",
    "UnavailableCallsTelemetryOperations",
]
