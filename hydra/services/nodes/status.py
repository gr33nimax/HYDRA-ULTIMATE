"""One truthful verdict per node: healthy, warning, or deliberately withdrawn.

The list and the node card must answer "is this server fine?" without the operator
reading generations or digests. Reachability alone is not an answer: a node can be
reachable and still serve nothing, because its settings were never applied or its
client profiles were never published. This module is pure — it reads a desired node
and its last observation and returns words, so the same verdict is testable without a
terminal and without a VPS.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.observation import (
    CONTROL_ERROR,
    CONTROL_OK,
    CONTROL_UNKNOWN,
    STAGE_APPLY,
    STAGE_CONNECT,
    STAGE_EXPORT,
    STAGE_PUBLISH,
    STAGE_UPGRADE,
    NodeObservation,
)

# A node the operator withdrew is not broken, so it gets its own level instead of
# being shown as a failure the operator would try to fix.
LEVEL_HEALTHY = "healthy"
LEVEL_WARNING = "warning"
LEVEL_WITHDRAWN = "withdrawn"

# The base polls nodes on its five-minute schedule; two missed cycles without a new
# fact means the verdict is about the past, not about the node.
STALE_AFTER_SECONDS = 600

STAGE_LABELS = {
    STAGE_CONNECT: "связь",
    STAGE_APPLY: "применение настроек",
    STAGE_EXPORT: "подготовка профилей",
    STAGE_PUBLISH: "публикация",
    STAGE_UPGRADE: "обновление",
}


@dataclass(frozen=True)
class NodeStatus:
    """What the operator should read, and the fact it was derived from."""

    level: str
    reason: str = ""
    checked_at: str = ""

    @property
    def healthy(self) -> bool:
        return self.level == LEVEL_HEALTHY


def age_seconds(stamp: object, *, now: datetime | None = None) -> float | None:
    """Age of a timestamp in seconds, or None when it cannot be trusted."""
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (reference - moment).total_seconds()


def age_text(seconds: float | None) -> str:
    if seconds is None:
        return ""
    if seconds < 0:
        return "только что"
    # ``seconds`` is a float here, so the conversions below cannot raise.
    minutes = int(seconds // 60)
    hours = int(seconds // 3600)
    days = int(seconds // 86400)
    if seconds < 90:
        return f"{int(seconds)} с назад"
    if seconds < 5400:
        return f"{minutes} мин назад"
    if seconds < 172800:
        return f"{hours} ч назад"
    return f"{days} дн назад"


def status_of(
    node: NodeConfig,
    observation: NodeObservation | None,
    *,
    now: datetime | None = None,
) -> NodeStatus:
    """Derive the node's verdict from desired configuration and the last contact."""
    if node.withdrawn:
        return NodeStatus(LEVEL_WITHDRAWN, "убрана из подписки", _stamp(observation))
    checked_at = _stamp(observation)
    if observation is None or observation.control == CONTROL_UNKNOWN:
        return NodeStatus(LEVEL_WARNING, "нет данных проверки", "")
    if observation.control == CONTROL_ERROR:
        return NodeStatus(LEVEL_WARNING, _failure_reason(observation), checked_at)
    if observation.control != CONTROL_OK:
        return NodeStatus(LEVEL_WARNING, "неизвестный результат проверки", checked_at)
    for problem in _pending_reasons(node, observation):
        return NodeStatus(LEVEL_WARNING, problem, checked_at)
    seconds = age_seconds(checked_at, now=now)
    if seconds is None:
        return NodeStatus(LEVEL_WARNING, "время проверки недостоверно", checked_at)
    if seconds > STALE_AFTER_SECONDS:
        return NodeStatus(LEVEL_WARNING, f"проверка устарела · {age_text(seconds)}", checked_at)
    return NodeStatus(LEVEL_HEALTHY, "", checked_at)


def _stamp(observation: NodeObservation | None) -> str:
    return str(getattr(observation, "checked_at", "") or "")


def _failure_reason(observation: NodeObservation) -> str:
    stage = str(observation.stage or "")
    if stage == STAGE_CONNECT:
        return "нет связи"
    label = STAGE_LABELS.get(stage, stage or "операция")
    message = str(observation.message or "").strip()
    return f"{label} не выполнено: {message}" if message else f"{label} не выполнено"


def _pending_reasons(node: NodeConfig, observation: NodeObservation) -> list[str]:
    """Facts that keep a reachable node from being called healthy."""
    reasons: list[str] = []
    if node.published_generation <= 0 or not node.published_digest:
        reasons.append("профили не опубликованы")
    elif node.published_generation < node.generation:
        reasons.append(f"изменения ждут применения · поколение {node.generation}")
    if observation.upgrade in {"scheduled", "pending"}:
        reasons.append("обновление не завершено")
    uncovered = sorted(name for name, count in observation.coverage.items() if count <= 0)
    if uncovered:
        reasons.append("профили не готовы: " + ", ".join(uncovered))
    for warning in observation.warnings:
        reasons.append(str(warning))
    return reasons


def summary_line(status: NodeStatus) -> str:
    """The list line: one word plus the shortest useful explanation."""
    if status.level == LEVEL_HEALTHY:
        return "healthy"
    if status.level == LEVEL_WITHDRAWN:
        return "убрана из подписки"
    return f"warning · {status.reason}" if status.reason else "warning"


__all__ = [
    "LEVEL_HEALTHY",
    "LEVEL_WARNING",
    "LEVEL_WITHDRAWN",
    "STAGE_LABELS",
    "STALE_AFTER_SECONDS",
    "NodeStatus",
    "age_seconds",
    "age_text",
    "status_of",
    "summary_line",
]
