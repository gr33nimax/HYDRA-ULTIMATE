"""Monotonic per-user and protocol-wide traffic accounting.

Live plugin counters are snapshots and may reset after a restart or log rotation.
This module converts those snapshots to deltas and keeps authoritative totals
in per-user credentials or aggregate protocol counters when attribution is not
technically reliable (for example qWDTT).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from hydra.core.state import update_state
from hydra.core.state_models import AppState, User, find_user
from hydra.services.traffic_accounting import (
    _legacy_protocol_totals,
    ensure_report_totals,
    record_report_delta,
)

class TrafficProtocolAccess(Protocol):
    """Runtime counter capabilities needed by traffic accounting."""

    def enabled_names(self, state: AppState) -> set[str]: ...
    def traffic(self, state: AppState, name: str) -> dict[str, int]: ...
    def traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> dict[str, int] | None: ...
    def traffic_source_reason(
        self,
        state: AppState,
        name: str,
    ) -> str: ...
    def aggregate_traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> int | None: ...
    def ingest_traffic(
        self,
        state: AppState,
        name: str,
        cursors: dict,
    ) -> None: ...


class TrafficOperations(Protocol):
    def refresh(self, state: AppState) -> dict[str, int]: ...
    def refresh_state(self) -> AppState: ...
    def collect(self, state: AppState | None = None) -> dict[str, int]: ...
    def protocol_totals(self, state: AppState) -> dict[str, int]: ...
    def source_availability(self, state: AppState) -> dict[str, str]: ...
    def check_limits(self, state: AppState) -> list[str]: ...
    def reset_global_report_state(self) -> AppState: ...
    def reset_user_traffic_state(self, email: str) -> AppState: ...


@dataclass(frozen=True)
class UnavailableTrafficOperations:
    """Fail clearly when a manually assembled application omits accounting."""

    def _unavailable(self):
        raise RuntimeError("traffic service is unavailable")

    def refresh(self, state: AppState) -> dict[str, int]:
        return self._unavailable()

    def refresh_state(self) -> AppState:
        return self._unavailable()

    def collect(self, state: AppState | None = None) -> dict[str, int]:
        return self._unavailable()

    def protocol_totals(self, state: AppState) -> dict[str, int]:
        return self._unavailable()

    def source_availability(self, state: AppState) -> dict[str, str]:
        return self._unavailable()

    def check_limits(self, state: AppState) -> list[str]:
        return self._unavailable()

    def reset_global_report_state(self) -> AppState:
        return self._unavailable()

    def reset_user_traffic_state(self, email: str) -> AppState:
        return self._unavailable()


@dataclass(frozen=True)
class TrafficService:
    """Application service for monotonic traffic accounting."""

    protocols: TrafficProtocolAccess

    def refresh(self, state: AppState) -> dict[str, int]:
        return refresh_user_traffic(state, protocols=self.protocols)

    def refresh_state(self) -> AppState:
        return refresh_traffic_state(protocols=self.protocols)

    def collect(self, state: AppState | None = None) -> dict[str, int]:
        return collect_traffic(state, protocols=self.protocols)

    def protocol_totals(self, state: AppState) -> dict[str, int]:
        return protocol_totals(state)

    def source_availability(self, state: AppState) -> dict[str, str]:
        """Report per-protocol counter-source reasons from the last refresh."""
        reader = getattr(self.protocols, "traffic_source_reason", None)
        if not callable(reader):
            return {}
        reasons: dict[str, str] = {}
        for name in sorted(self.protocols.enabled_names(state)):
            try:
                reasons[name] = str(reader(state, name) or "")
            except Exception:
                # A protocol that cannot even explain itself is unavailable.
                reasons[name] = "источник недоступен"
        return reasons

    def check_limits(self, state: AppState) -> list[str]:
        return check_traffic_limits(state, protocols=self.protocols)

    def reset_global_report_state(self) -> AppState:
        return reset_global_report_state()

    def reset_user_traffic_state(self, email: str) -> AppState:
        return reset_user_traffic_state(email)


def _as_non_negative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _accumulate_snapshot(state: AppState, protocol: str,
                         snapshot: dict[str, int]) -> None:
    """Convert a resettable absolute counter to a monotonic stored total."""
    users = {user.email: user for user in state.users}
    for email, raw_value in snapshot.items():
        user = users.get(email)
        if user is None:
            continue
        raw = _as_non_negative_int(raw_value)
        stats = user.credentials.setdefault(protocol, {})
        previous_raw = stats.get("traffic_last_raw_bytes")
        accumulated = _as_non_negative_int(stats.get("traffic_used_bytes", 0))
        if previous_raw is None:
            # Migration from the old snapshot-only accounting model.
            accumulated = max(accumulated, raw)
        else:
            previous_raw = _as_non_negative_int(previous_raw)
            # A lower value means that the interface/process counter reset.
            accumulated += raw - previous_raw if raw >= previous_raw else raw
        stats["traffic_last_raw_bytes"] = raw
        stats["traffic_used_bytes"] = accumulated


def _accumulate_protocol_total(state: AppState, protocol: str, raw_value: object) -> None:
    """Convert a resettable protocol-wide counter to a monotonic total."""
    raw = _as_non_negative_int(raw_value)
    protocols = state.install.setdefault("protocol_traffic_totals", {})
    stats = protocols.setdefault(protocol, {})
    previous_raw = stats.get("traffic_last_raw_bytes")
    accumulated = _as_non_negative_int(stats.get("traffic_used_bytes", 0))
    if previous_raw is None:
        accumulated = max(accumulated, raw)
    else:
        previous_raw = _as_non_negative_int(previous_raw)
        accumulated += raw - previous_raw if raw >= previous_raw else raw
    stats["traffic_last_raw_bytes"] = raw
    stats["traffic_used_bytes"] = accumulated


def refresh_user_traffic(
    state: AppState,
    *,
    protocols: TrafficProtocolAccess,
) -> dict[str, int]:
    """Refresh resettable sources and rebuild authoritative user totals."""
    enabled_names = protocols.enabled_names(state)
    ensure_report_totals(state)
    cursor_root = state.install.setdefault("traffic_log_cursors", {})
    for protocol in sorted(enabled_names):
        before = _protocol_total(state, protocol)
        try:
            protocols.ingest_traffic(
                state,
                protocol,
                cursor_root.setdefault(protocol, {}),
            )
        except Exception:
            # A plugin-owned event source must not block other accounting.
            pass
        try:
            snapshot = protocols.traffic_snapshot(state, protocol)
            if snapshot is not None:
                _accumulate_snapshot(state, protocol, snapshot)
        except Exception:
            # Keep the last good totals when a runtime counter is unavailable.
            pass
        try:
            raw = protocols.aggregate_traffic_snapshot(
                state,
                protocol,
            )
            if raw is not None:
                _accumulate_protocol_total(state, protocol, raw)
        except Exception:
            # Preserve the last good aggregate when the interface disappears
            # briefly during a service restart.
            pass
        record_report_delta(
            state,
            protocol,
            max(0, _protocol_total(state, protocol) - before),
        )

    totals: dict[str, int] = {}
    for user in state.users:
        total = 0
        for stats in user.credentials.values():
            if isinstance(stats, dict):
                total += _as_non_negative_int(stats.get("traffic_used_bytes", 0))
        # Never reduce an existing total during migration or a partial outage.
        user.traffic_used_bytes = max(_as_non_negative_int(user.traffic_used_bytes), total)
        totals[user.email] = user.traffic_used_bytes
    return totals


def refresh_traffic_state(*, protocols: TrafficProtocolAccess) -> AppState:
    """Atomically refresh and persist traffic, returning the latest state."""
    state, _ = update_state(
        lambda latest: refresh_user_traffic(latest, protocols=protocols),
    )
    return state


def collect_traffic(
    state: AppState | None = None,
    *,
    protocols: TrafficProtocolAccess,
) -> dict[str, int]:
    """Return authoritative totals; persist a refresh when no state is passed."""
    if state is None:
        state = refresh_traffic_state(protocols=protocols)
    else:
        refresh_user_traffic(state, protocols=protocols)
    return {user.email: user.traffic_used_bytes for user in state.users}


def update_user_traffic(
    state: AppState,
    *,
    protocols: TrafficProtocolAccess,
) -> None:
    """Backward-compatible in-memory refresh."""
    refresh_user_traffic(state, protocols=protocols)


def protocol_totals(state: AppState) -> dict[str, int]:
    reports = state.install.get("traffic_report_totals")
    if isinstance(reports, dict):
        return {
            str(protocol): _as_non_negative_int(used)
            for protocol, used in reports.items()
        }
    return _legacy_protocol_totals(state)


def _protocol_total(state: AppState, protocol: str) -> int:
    return _legacy_protocol_totals(state).get(protocol, 0)


def reset_global_report_traffic(state: AppState) -> None:
    """Start a new global reporting period without touching user quotas."""
    reports = ensure_report_totals(state)
    protocols = set(reports) | set(state.install.get("protocol_traffic_totals", {}))
    for protocol in protocols:
        reports[protocol] = 0
        stats = state.install.get("protocol_traffic_totals", {}).get(protocol)
        if isinstance(stats, dict):
            stats["traffic_used_bytes"] = 0


def reset_global_report_state() -> AppState:
    """Atomically persist a global reporting-period reset."""
    state, _ = update_state(reset_global_report_traffic)
    return state


def reset_user_traffic(state: AppState, email: str) -> User:
    """Start a user's quota period while retaining counter baselines."""
    user = find_user(state, email)
    if user is None:
        raise ValueError(f"user not found: {email}")
    ensure_report_totals(state)
    user.traffic_used_bytes = 0
    for stats in user.credentials.values():
        if not isinstance(stats, dict):
            continue
        for key in tuple(stats):
            if key.startswith("traffic_") and key != "traffic_last_raw_bytes":
                stats.pop(key, None)
        stats["traffic_used_bytes"] = 0
    resets = state.install.setdefault("traffic_user_reset_epochs", {})
    resets[email] = _as_non_negative_int(resets.get(email, 0)) + 1
    return user


def reset_user_traffic_state(email: str) -> AppState:
    """Atomically persist a user's quota-period reset."""
    state, _ = update_state(lambda latest: reset_user_traffic(latest, email))
    return state


def check_traffic_limits(
    state: AppState,
    *,
    protocols: TrafficProtocolAccess,
) -> list[str]:
    refresh_user_traffic(state, protocols=protocols)
    exceeded: list[str] = []
    for user in state.users:
        if user.blocked:
            continue
        try:
            limit_bytes = int(user.traffic_limit_gb * 1073741824)
        except (TypeError, ValueError) as exc:
            # A malformed quota must fail loudly, never silently disable itself.
            raise ValueError("invalid traffic limit") from exc
        if limit_bytes > 0 and user.traffic_used_bytes >= limit_bytes:
            exceeded.append(user.email)
    return exceeded
