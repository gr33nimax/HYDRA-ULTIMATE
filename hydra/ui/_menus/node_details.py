"""How a node's facts read on screen: one line per question the operator asks.

These helpers only format what a service already decided — they never call a service,
never touch state and never guess. Keeping them separate keeps the screens small and
lets the same wording be reused by the card, the list and the node's own diagnostics.
"""

from __future__ import annotations

from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.observation import CONTROL_ERROR, CONTROL_UNKNOWN, NodeObservation
from hydra.services.nodes.status import NodeStatus, age_seconds, age_text, status_of, summary_line

# Names for the stages an operation can fail at: a reason is useless without knowing
# which step of the way to a working subscription failed.
STAGE_LABELS = {
    "connect": "связь",
    "apply": "применение настроек",
    "export": "подготовка профилей",
    "publish": "публикация",
    "upgrade": "обновление",
}


def status_of_node(node: NodeConfig, observation: NodeObservation | None) -> NodeStatus:
    return status_of(node, observation)


def level_text(status: NodeStatus) -> str:
    """The verdict word alone; the explanation belongs on its own line."""
    if status.level == "healthy":
        return "healthy"
    if status.level == "withdrawn":
        return "убрана из подписки"
    return "warning"


def checked_at_text(status: NodeStatus) -> str:
    age = age_text(age_seconds(status.checked_at))
    return age or "не проверялась"


def list_lines(node: NodeConfig, observation: NodeObservation | None) -> list[str]:
    """Three readable lines: address, verdict, when it was last confirmed."""
    status = status_of_node(node, observation)
    return [node.address, f"{summary_line(status)} · {checked_at_text(status)}"]


def publication_row(node: NodeConfig) -> str:
    """Subscription inclusion depends on a confirmed export, not on reachability."""
    if node.withdrawn:
        return "убрана из подписки"
    if node.published_generation <= 0 or not node.published_digest:
        return "профили не опубликованы"
    if node.generation > node.published_generation:
        return f"опубликовано поколение {node.published_generation}; ждёт подтверждения {node.generation}"
    return f"опубликовано поколение {node.published_generation}"


def connection_row(observation: NodeObservation | None) -> str:
    """Reachability and the operation outcome, kept apart from each other."""
    control = getattr(observation, "control", CONTROL_UNKNOWN)
    age = age_text(age_seconds(getattr(observation, "checked_at", "")))
    if control == CONTROL_UNKNOWN or not isinstance(control, str):
        return "не проверялась"
    if control == CONTROL_ERROR:
        stage = str(getattr(observation, "stage", "") or "")
        if stage == "connect":
            return f"нет связи · {age}" if age else "нет связи"
        label = STAGE_LABELS.get(stage, stage or "операция")
        return f"есть связь, но {label} не выполнено · {age}" if age else f"есть связь, но {label} не выполнено"
    return f"доступна · {age}" if age else "доступна"


def reason_row(observation: NodeObservation | None) -> str:
    message = str(getattr(observation, "message", "") or "")
    if not message:
        return ""
    stage = str(getattr(observation, "stage", "") or "")
    return f"{STAGE_LABELS.get(stage, stage or 'операция')}: {message}"


def coverage_row(node: NodeConfig, observation: NodeObservation | None) -> str:
    base = publication_row(node)
    coverage = getattr(observation, "coverage", None)
    if not isinstance(coverage, dict) or not coverage:
        return base
    counts = ", ".join(f"{name}: {count}" for name, count in sorted(coverage.items()))
    return f"{base} · {counts}"


def short_revision(value: str) -> str:
    return value[:12] if value else ""


def upgrade_row(node: NodeConfig, observation: NodeObservation | None) -> str:
    """What the node runs against what the base asked for.

    Scheduling an upgrade only starts a worker, so "запланировано" and "выполнено" are
    different answers and only the node's own revision marker can tell them apart.
    """
    installed = str(getattr(observation, "installed_revision", "") or "")
    state = str(getattr(observation, "upgrade", "") or "")
    target = short_revision(node.revision)
    if state == "complete":
        return f"выполнено · установлено {short_revision(installed)}"
    if state == "pending":
        return f"ожидает · установлено {short_revision(installed)}, цель {target}"
    if state == "scheduled":
        return f"запланировано · цель {target}"
    if installed:
        return f"установлено {short_revision(installed)}"
    return f"не проверялось · цель {target}" if target else "не проверялось"


__all__ = [
    "STAGE_LABELS",
    "checked_at_text",
    "level_text",
    "connection_row",
    "coverage_row",
    "list_lines",
    "publication_row",
    "reason_row",
    "short_revision",
    "status_of_node",
    "upgrade_row",
]
