"""Runtime-only scheduling state for rate-safe HydraVK room probes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, cast

from hydra.core.host import HostBackend


ProbeOutcome = Literal[
    "healthy",
    "dead",
    "network",
    "rate_limited",
    "captcha",
    "error",
]
PROBE_OUTCOMES: frozenset[str] = frozenset(
    {
        "healthy",
        "dead",
        "network",
        "rate_limited",
        "captcha",
        "error",
    }
)
PROBE_INTERVAL = timedelta(hours=6)
CONFIRMATION_DELAY = timedelta(minutes=15)
MIN_START_INTERVAL = timedelta(minutes=1)


@dataclass(frozen=True)
class ProbeDecision:
    slot: int
    confirmation: bool


@dataclass
class CallsProbeStore:
    """Persist only redacted probe scheduling metadata, never desired state."""

    host: HostBackend
    path: Path

    def claim_due(self, hashes: list[str], *, now: datetime) -> ProbeDecision | None:
        state = self._normalized_state(hashes)
        last_started = self._timestamp(state.get("last_started_at"))
        if last_started and now - last_started < MIN_START_INTERVAL:
            return None
        records = cast(dict[str, dict[str, str]], state["records"])
        for slot in range(1, len(hashes) + 1):
            record = records[str(slot)]
            confirmation_due = self._timestamp(record.get("confirmation_due_at"))
            if confirmation_due and confirmation_due <= now:
                state["last_started_at"] = self._format(now)
                self._save(state)
                return ProbeDecision(slot, True)
        due = [
            (self._timestamp(records[str(slot)].get("last_checked_at")), slot)
            for slot in range(1, len(hashes) + 1)
            if self._is_regularly_due(records[str(slot)], now)
        ]
        if not due:
            return None
        _, slot = min(due, key=lambda item: item[0] or datetime.min.replace(tzinfo=timezone.utc))
        state["last_started_at"] = self._format(now)
        self._save(state)
        return ProbeDecision(slot, False)

    def record(
        self,
        hashes: list[str],
        decision: ProbeDecision,
        outcome: ProbeOutcome,
        *,
        now: datetime,
    ) -> None:
        if outcome not in PROBE_OUTCOMES:
            raise ValueError(f"unknown Calls probe outcome: {outcome}")
        if not 1 <= decision.slot <= len(hashes):
            raise ValueError("Calls probe slot is outside the managed pool")
        state = self._normalized_state(hashes)
        records = cast(dict[str, dict[str, str]], state["records"])
        record = records[str(decision.slot)]
        record["last_checked_at"] = self._format(now)
        record["last_outcome"] = outcome
        if outcome == "dead" and not decision.confirmation:
            record["confirmation_due_at"] = self._format(now + CONFIRMATION_DELAY)
        else:
            record.pop("confirmation_due_at", None)
        self._save(state)

    def reset(self) -> None:
        self.host.remove_file(self.path, missing_ok=True)

    def status(self, hashes: list[str]) -> dict[str, object]:
        """Return only aggregate, redacted runtime health for operator status."""
        state = self._normalized_state(hashes)
        records = cast(dict[str, dict[str, str]], state["records"])
        values = list(records.values())
        checked = [str(value.get("last_checked_at", "")) for value in values if value.get("last_checked_at")]
        latest = max(values, key=lambda value: str(value.get("last_checked_at", "")), default={})
        return {
            "last_checked_at": max(checked, default=""),
            "last_outcome": str(latest.get("last_outcome", "")),
            "confirmation_pending": any(bool(value.get("confirmation_due_at")) for value in values),
        }

    def _normalized_state(self, hashes: list[str]) -> dict[str, object]:
        if not hashes:
            return {"records": {}}
        source = self._load()
        raw_records = source.get("records")
        records = raw_records if isinstance(raw_records, dict) else {}
        normalized: dict[str, dict[str, str]] = {}
        for slot, value in enumerate(hashes, start=1):
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            previous = records.get(str(slot))
            record = previous.copy() if isinstance(previous, dict) else {}
            if record.get("hash") != digest:
                record = {"hash": digest}
            normalized[str(slot)] = {
                key: value for key, value in record.items() if isinstance(key, str) and isinstance(value, str)
            }
        last_started = source.get("last_started_at")
        return {
            "last_started_at": last_started if isinstance(last_started, str) else "",
            "records": normalized,
        }

    def _is_regularly_due(self, record: dict[str, str], now: datetime) -> bool:
        return (
            not (last_checked := self._timestamp(record.get("last_checked_at"))) or now - last_checked >= PROBE_INTERVAL
        )

    def _load(self) -> dict[str, object]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _save(self, state: dict[str, object]) -> None:
        self.host.atomic_write(
            self.path,
            json.dumps(state, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )

    @staticmethod
    def _format(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _timestamp(value: object) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
