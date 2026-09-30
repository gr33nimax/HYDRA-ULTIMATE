"""Runtime observations for managed nodes, kept outside desired state.

Reachability, apply outcome and publication integrity are runtime projections: they
change without the operator asking anything, so they must never be written into
``state.json``, whose contents are the desired configuration. The TUI reads this store
so a node does not fall back to "не проверена" on every visit, and the sync cycle fills
it while it already reconciles the nodes.

Observations are diagnostics: every operation here is best-effort, bounded and redacted.
A failure to record must never break the operation that was being reported.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hydra.core.host import HostBackend
from hydra.services.nodes.control_client import NodeControlError
from hydra.services.nodes.snapshot_store import SnapshotStoreError
from hydra.utils.commands import redact_text

_LOGGER = logging.getLogger(__name__)

MAX_MESSAGE = 512
MAX_OBSERVATIONS = 64

# Stable identifiers: a UI or a report must be able to switch on them.
CONTROL_UNKNOWN = "unknown"
CONTROL_OK = "ok"
CONTROL_ERROR = "error"

STAGE_CONNECT = "connect"
STAGE_APPLY = "apply"
STAGE_EXPORT = "export"
STAGE_PUBLISH = "publish"
STAGE_UPGRADE = "upgrade"


@dataclass(frozen=True)
class NodeObservation:
    """What was last seen about one node, and when."""

    node_id: str
    checked_at: str = ""
    last_success_at: str = ""
    control: str = CONTROL_UNKNOWN
    stage: str = ""
    code: str = ""
    message: str = ""
    applied_generation: int = 0
    published_generation: int = 0
    coverage: dict[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    target_revision: str = ""
    installed_revision: str = ""
    upgrade: str = ""

    @property
    def published(self) -> bool:
        return self.published_generation > 0

    @property
    def ready(self) -> bool:
        """Reachability is not readiness: a node is ready only when it publishes."""
        return self.control == CONTROL_OK and self.published and not self.message

    def to_document(self) -> dict[str, Any]:
        document = asdict(self)
        document["warnings"] = list(self.warnings)
        return document

    @classmethod
    def from_document(cls, raw: object, *, node_id: str = "") -> "NodeObservation":
        """Read one stored observation, ignoring anything that is not shaped like one."""
        if not isinstance(raw, dict):
            return cls(node_id=node_id)
        coverage = raw.get("coverage")
        warnings = raw.get("warnings")
        return cls(
            node_id=str(raw.get("node_id") or node_id)[:128],
            checked_at=_text(raw.get("checked_at")),
            last_success_at=_text(raw.get("last_success_at")),
            control=_choice(raw.get("control"), (CONTROL_OK, CONTROL_ERROR), CONTROL_UNKNOWN),
            stage=_text(raw.get("stage"))[:32],
            code=_text(raw.get("code"))[:64],
            message=_text(raw.get("message")),
            applied_generation=_count(raw.get("applied_generation")),
            published_generation=_count(raw.get("published_generation")),
            coverage={str(key)[:64]: _count(value) for key, value in coverage.items()}
            if isinstance(coverage, dict)
            else {},
            warnings=tuple(str(item)[:128] for item in warnings) if isinstance(warnings, list) else (),
            target_revision=_text(raw.get("target_revision"))[:64],
            installed_revision=_text(raw.get("installed_revision"))[:64],
            upgrade=_text(raw.get("upgrade"))[:32],
        )


def _text(value: object) -> str:
    return redact_text(str(value))[:MAX_MESSAGE] if value not in (None, "") else ""


def _count(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _choice(value: object, allowed: tuple[str, ...], default: str) -> str:
    text = str(value or "")
    return text if text in allowed else default


def describe_failure(exc: BaseException) -> tuple[str, str]:
    """Map an operation failure onto a stable stage and code.

    The operator needs to know whether the node was unreachable, refused the
    configuration, could not produce profiles or could not be stored — four different
    problems that all used to read as one sentence about a failed operation.
    """
    message = str(exc)
    if isinstance(exc, NodeControlError):
        return STAGE_CONNECT, "control_unavailable"
    if isinstance(exc, SnapshotStoreError):
        return STAGE_PUBLISH, "publication_storage"
    if "no client profiles" in message:
        return STAGE_EXPORT, "empty_export"
    if "health or contract" in message or "contract check failed" in message:
        return STAGE_CONNECT, "health_or_contract"
    if "did not confirm" in message or "stale generation" in message:
        return STAGE_APPLY, "apply_not_confirmed"
    if "desired state changed" in message:
        return STAGE_PUBLISH, "desired_state_changed"
    return STAGE_APPLY, "operation_failed"


@dataclass
class NodeObservationStore:
    """Bounded, host-backed storage for node observations."""

    host: HostBackend
    path: Path
    max_observations: int = MAX_OBSERVATIONS
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.path.is_absolute():
            raise ValueError("observation path must be an absolute path")
        if type(self.max_observations) is not int or self.max_observations < 1:
            raise ValueError("max_observations must be a positive integer")

    def load(self) -> dict[str, NodeObservation]:
        """Read every stored observation; an unreadable file reads as empty."""
        try:
            raw = self.path.read_bytes()
        except OSError:
            return {}
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            _LOGGER.warning("Node observations are unreadable; starting from none")
            return {}
        if not isinstance(document, dict):
            return {}
        nodes = document.get("nodes")
        if not isinstance(nodes, dict):
            return {}
        return {
            str(node_id): NodeObservation.from_document(value, node_id=str(node_id)) for node_id, value in nodes.items()
        }

    def get(self, node_id: str) -> NodeObservation | None:
        return self.load().get(node_id)

    def record(self, node_id: str, **changes: Any) -> NodeObservation:
        """Merge one operation outcome into the node's observation."""
        observations = self.load()
        current = observations.get(node_id, NodeObservation(node_id=node_id))
        changes.setdefault("checked_at", self._stamp())
        updated = _replace(current, node_id=node_id, **changes)
        observations[node_id] = updated
        self._save(observations)
        return updated

    def forget(self, node_id: str) -> None:
        observations = self.load()
        if node_id not in observations:
            return
        del observations[node_id]
        self._save(observations)

    def succeeded(self, node_id: str, **changes: Any) -> NodeObservation:
        """Record a success, which also refreshes the last-good timestamp."""
        return self.record(
            node_id,
            control=CONTROL_OK,
            stage="",
            code="",
            message="",
            last_success_at=self._stamp(),
            **changes,
        )

    def failed(self, node_id: str, exc: BaseException, **changes: Any) -> NodeObservation:
        stage, code = describe_failure(exc)
        return self.record(
            node_id,
            control=CONTROL_ERROR,
            stage=stage,
            code=code,
            message=redact_text(str(exc))[:MAX_MESSAGE] or exc.__class__.__name__,
            **changes,
        )

    def _stamp(self) -> str:
        return self.now().isoformat()

    def _save(self, observations: dict[str, NodeObservation]) -> None:
        retained = sorted(
            observations.items(),
            key=lambda item: item[1].checked_at,
            reverse=True,
        )[: self.max_observations]
        document = {"nodes": {node_id: observation.to_document() for node_id, observation in retained}}
        try:
            payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.host.atomic_write(self.path, payload, mode=0o600, durable=False)
        except Exception:
            _LOGGER.warning("Node observations could not be recorded (%s)", "write failed")


def _replace(observation: NodeObservation, **changes: Any) -> NodeObservation:
    """Return the observation with the given fields replaced, ignoring empty values."""
    known = set(NodeObservation.__dataclass_fields__)
    merged = {field_name: getattr(observation, field_name) for field_name in known}
    for key, value in changes.items():
        if key in known and value is not None:
            merged[key] = value
    return NodeObservation(**merged)


__all__ = [
    "CONTROL_ERROR",
    "CONTROL_OK",
    "CONTROL_UNKNOWN",
    "MAX_MESSAGE",
    "NodeObservation",
    "NodeObservationStore",
    "STAGE_APPLY",
    "STAGE_CONNECT",
    "STAGE_EXPORT",
    "STAGE_PUBLISH",
    "STAGE_UPGRADE",
    "describe_failure",
]

def upgrade_state(node: Any, installed: str) -> dict[str, object]:
    """Compare the revision the node reports with the one the base asked for.

    Scheduling an upgrade only starts a worker; the operator needs the difference between
    "asked for" and "running", and that difference is only visible from the node's own
    revision marker.
    """
    if not installed:
        return {"installed_revision": "", "upgrade": "unknown"}
    target = str(getattr(node, "revision", "") or "")
    if not target:
        return {"installed_revision": installed, "upgrade": ""}
    return {
        "installed_revision": installed,
        "upgrade": "complete" if installed == target else "pending",
    }


def published_coverage(export: Any) -> dict[str, int]:
    """Count the profiles a published snapshot actually carries, per protocol."""
    if export is None:
        return {}
    counts: dict[str, int] = {}
    for exported_user in getattr(export, "users", {}).values():
        for profile in getattr(exported_user, "profiles", ()):
            name = getattr(profile, "protocol", "")
            if name:
                counts[name] = counts.get(name, 0) + 1
    return counts


def record_sync(
    store: NodeObservationStore | None,
    node: Any,
    result: Any,
    coverage: Callable[[], dict[str, int]] | None = None,
) -> None:
    """Record a completed reconcile, keeping coverage meaningful across "unchanged".

    An unchanged reconcile carries no new counts, and overwriting the last known numbers
    with nothing is what made a serving node look empty in the operator's view.
    """
    if store is None:
        return
    node_id = str(getattr(node, "id", ""))
    changes: dict[str, object] = {
        "applied_generation": int(getattr(node, "generation", 0) or 0),
        "published_generation": int(getattr(node, "published_generation", 0) or 0),
        "target_revision": str(getattr(node, "revision", "") or ""),
    }
    installed = str(getattr(result, "installed_revision", "") or "")
    if installed:
        changes.update(upgrade_state(node, installed))
    if str(getattr(result, "status", "")) == "published":
        changes["coverage"] = dict(getattr(result, "coverage", {}) or {})
        changes["warnings"] = tuple(getattr(result, "warnings", ()) or ())
    else:
        previous = store.get(node_id)
        known = dict(previous.coverage) if previous is not None else {}
        if not known and coverage is not None:
            known = coverage()
        changes["coverage"] = known
    store.succeeded(node_id, **changes)


def record_current_apply_error(store: NodeObservationStore | None, client: Any) -> None:
    """Surface a node that accepted a generation but cannot serve it.

    A node answers ``/health`` while its last apply failed, so reachability alone made it
    look healthy. Its own diagnostics carry the reason, and asking for it is what turns
    "published" into "published and actually serving".
    """
    if store is None:
        return
    try:
        diagnostics = client.diagnostics()
    except Exception:
        return
    last_error = diagnostics.get("last_error") if isinstance(diagnostics, dict) else ""
    if isinstance(last_error, str) and last_error.strip():
        store.record(
            str(getattr(client, "node_id", "")),
            control=CONTROL_OK,
            stage=STAGE_APPLY,
            code="node_apply_error",
            message=last_error[:2048],
        )


def record_check(
    store: NodeObservationStore | None,
    node: Any,
    generation: int,
    last_error: str,
    installed: str = "",
) -> None:
    """Record one explicit connectivity check, with the node's own apply error kept apart."""
    if store is None:
        return
    node_id = str(getattr(node, "id", ""))
    changes: dict[str, object] = {
        "applied_generation": generation,
        "target_revision": str(getattr(node, "revision", "") or ""),
    }
    if installed:
        # A check is also the cheapest way to learn which revision the node runs.
        changes.update(upgrade_state(node, installed))
    if last_error:
        store.record(
            node_id,
            control=CONTROL_OK,
            stage=STAGE_APPLY,
            code="node_apply_error",
            message=last_error[:2048],
            **changes,
        )
        return
    store.succeeded(node_id, **changes)

