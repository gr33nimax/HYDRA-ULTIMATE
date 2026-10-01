"""One truthful verdict per node, derived only from desired config and last contact."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from hydra.core.state_nodes import NodeConfig, MANAGEMENT_WITHDRAWN
from hydra.services.nodes.observation import NodeObservation
from hydra.services.nodes.status import (
    LEVEL_HEALTHY,
    LEVEL_WARNING,
    LEVEL_WITHDRAWN,
    STALE_AFTER_SECONDS,
    age_seconds,
    age_text,
    status_of,
    summary_line,
)


def _published(**changes) -> NodeConfig:
    values = {
        "id": "uk-1",
        "name": "UK",
        "address": "node.example.com",
        "generation": 2,
        "published_generation": 2,
        "published_digest": "a" * 64,
    }
    values.update(changes)
    return NodeConfig(**values)


def _seen(**changes) -> NodeObservation:
    values = {
        "node_id": "uk-1",
        "control": "ok",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "published_generation": 2,
    }
    values.update(changes)
    return NodeObservation(**values)


def test_no_observation_is_a_warning_not_a_healthy_node():
    status = status_of(_published(), None)
    assert status.level == LEVEL_WARNING
    assert status.reason == "нет данных проверки"
    assert summary_line(status) == "warning · нет данных проверки"


def test_reachability_alone_is_not_health_when_profiles_are_not_published():
    node = _published(published_generation=0, published_digest="")
    status = status_of(node, _seen())
    assert status.level == LEVEL_WARNING
    assert status.reason == "профили не опубликованы"


def test_pending_generation_and_unfinished_upgrade_keep_the_node_in_warning():
    node = _published(generation=3)
    assert "ждут применения" in status_of(node, _seen()).reason
    assert status_of(_published(), _seen(upgrade="scheduled")).reason == "обновление не завершено"
    assert status_of(_published(), _seen(upgrade="pending")).reason == "обновление не завершено"


def test_uncovered_protocols_and_warnings_are_reported_not_hidden():
    status = status_of(_published(), _seen(coverage={"amneziawg": 2, "vless": 0}))
    assert status.level == LEVEL_WARNING
    assert "vless" in status.reason

    warned = status_of(_published(), _seen(warnings=("users_without_profiles=1",)))
    assert warned.reason == "users_without_profiles=1"


def test_a_fully_confirmed_cycle_is_healthy():
    status = status_of(_published(), _seen(coverage={"amneziawg": 2}))
    assert status.level == LEVEL_HEALTHY
    assert status.reason == ""
    assert summary_line(status) == "healthy"
    assert status.checked_at


def test_stale_and_untrusted_timestamps_are_not_recent_contact():
    old = (datetime.now(timezone.utc) - timedelta(seconds=STALE_AFTER_SECONDS + 60)).isoformat()
    status = status_of(_published(), _seen(checked_at=old))
    assert status.level == LEVEL_WARNING
    assert status.reason.startswith("проверка устарела")

    naive = status_of(_published(), _seen(checked_at="2026-09-30T12:00:00"))
    assert naive.reason == "время проверки недостоверно"
    assert age_seconds("2026-09-30T12:00:00") is None


def test_connection_failure_is_reported_with_its_real_stage():
    offline = status_of(_published(), _seen(control="error", stage="connect", message="control unavailable"))
    assert offline.reason == "нет связи"

    refused = status_of(_published(), _seen(control="error", stage="apply", message="S3=0"))
    assert refused.reason == "применение настроек не выполнено: S3=0"


def test_a_withdrawn_node_is_not_shown_as_a_broken_one():
    node = _published(management=MANAGEMENT_WITHDRAWN)
    status = status_of(node, _seen())
    assert status.level == LEVEL_WITHDRAWN
    assert summary_line(status) == "убрана из подписки"


def test_age_text_is_human_and_never_negative():
    assert age_text(None) == ""
    assert age_text(-5) == "только что"
    assert age_text(30) == "30 с назад"
    assert age_text(600) == "10 мин назад"
    assert age_text(7200) == "2 ч назад"
    assert age_text(200000) == "2 дн назад"


def test_status_accepts_a_plain_observation_like_object():
    """The service report must not require the exact dataclass to be useful."""
    observation = SimpleNamespace(
        control="ok",
        checked_at=datetime.now(timezone.utc).isoformat(),
        stage="",
        message="",
        coverage={},
        warnings=(),
        upgrade="",
        installed_revision="",
    )
    assert status_of(_published(), observation).level == LEVEL_HEALTHY
