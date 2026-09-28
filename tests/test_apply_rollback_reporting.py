"""A failed rollback callback must be visible and must not hide the apply error."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.state import AppState
from hydra.services.configuration import ConfigurationApplier

PLUGIN = "plugin mtproto_zig"
ORIGINAL = "Проверка сервисов не пройдена: mtproto_zig: route is not active"


def test_rollback_reports_a_callback_that_returns_false():
    errors: list[str] = []
    ran: list[str] = []
    transaction = ApplyTransaction()
    transaction.add_rollback(PLUGIN, lambda: False, priority=10)
    transaction.add_rollback("healthy", lambda: ran.append("healthy"), priority=20)

    failures = transaction.rollback(errors.append)

    assert [(item.action, item.error) for item in failures] == [
        (PLUGIN, "rollback step reported failure"),
    ]
    assert ran == ["healthy"], "a reported failure must not stop later rollbacks"
    assert errors == [f"Rollback {PLUGIN} failed: rollback step reported failure"]


class _Registry:
    """One plugin whose rollback reports failure; every other step succeeds."""

    def __init__(self) -> None:
        self.plugin = SimpleNamespace(
            meta=SimpleNamespace(name="mtproto_zig"),
            apply_failure=lambda: "",
        )
        self.rollbacks = 0

    def collect_fragments(self, state):
        del state
        return {}

    def enabled(self, state):
        del state
        return [self.plugin]

    def apply_enabled(self, state):
        del state
        return [(self.plugin, {"old": True})]

    def health_all(self, state):
        del state
        return {"mtproto_zig": "route is not active"}

    def rollback(self, plugin, state, snapshot):
        del plugin, state, snapshot
        self.rollbacks += 1
        return False


def test_a_failed_plugin_rollback_is_journaled_without_hiding_the_apply_error(tmp_path):
    """The original cause stays the apply error; the journal names the failed rollback."""
    journal: list[tuple[str, dict]] = []
    logged: list[str] = []
    apply_error = {"value": ""}
    registry = _Registry()
    singbox = SimpleNamespace(
        SINGBOX_CONFIG=tmp_path / "config.json",
        generate_config=lambda state, fragments: {},
        write_config=lambda config: True,
        reload=lambda: True,
        log=lambda level, message: logged.append(f"{level}: {message}"),
        last_error=lambda: "",
    )
    nft = SimpleNamespace(
        snapshot_tproxy=lambda: object(),
        apply_tproxy=lambda fragments, port: None,
        restore_tproxy=lambda snapshot: None,
    )
    applier = ConfigurationApplier(
        registry=registry,
        singbox=singbox,
        nft=nft,
        save_state=lambda state: None,
        set_apply_error=lambda message: apply_error.update(value=message),
        last_apply_error=lambda: apply_error["value"],
        journal=lambda event, **fields: journal.append((event, fields)),
        manage_traffic_daemon=lambda state: None,
        migrate_haproxy=lambda state: None,
    )

    with (
        patch("hydra.core.sni_router.needs_mux", return_value=True),
        patch("hydra.core.sni_router.rebuild", return_value=True),
        patch(
            "hydra.core.sni_router.snapshot_runtime",
            return_value=SimpleNamespace(config=None, caddy_unit=None),
        ),
    ):
        assert applier.apply(AppState()) is False

    assert registry.rollbacks == 1
    assert apply_error["value"] == ORIGINAL, "the real failure must stay the apply error"
    events = dict(journal)
    assert events["rolled_back"]["error"] == ORIGINAL
    assert events["rollback_failed"]["error"] == ORIGINAL
    assert events["rollback_failed"]["failures"] == [
        f"{PLUGIN}: rollback step reported failure",
    ]
    assert any("rollback step reported failure" in message for message in logged)
    assert journal[-1][0] == "rollback_failed", "the journal must not end on a clean rolled_back"
