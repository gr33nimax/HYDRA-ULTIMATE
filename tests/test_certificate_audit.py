"""Daily TLS certificate expiry audit and its sync-agent phase."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from hydra.core.state import AppState, PluginState
from hydra.services.certificate_audit import (
    CertificateInspector,
    CertificateStatus,
    collect_domains,
    parse_not_after,
    summarize,
)
from hydra.services.sync_cycle import run_sync_cycle
from hydra.services.sync_ports import SyncOperations


class _Reader:
    def __init__(self, present: set[str] | None = None) -> None:
        self.present = present

    def is_file(self, path: str) -> bool:
        return True if self.present is None else path in self.present


class _Host:
    """Fake host answering ``openssl x509 -enddate`` for known files."""

    def __init__(self, expiry: dict[str, str], *, openssl: bool = True) -> None:
        self.expiry = expiry
        self.openssl = openssl
        self.commands: list[list[str]] = []

    def which(self, executable: str) -> str | None:
        return "/usr/bin/openssl" if self.openssl else None

    def run(self, args, **_kwargs):
        command = [str(item) for item in args]
        self.commands.append(command)
        certificate = command[-1]
        if certificate not in self.expiry:
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(
            returncode=0,
            stdout=f"notAfter={self.expiry[certificate]}\n",
        )


def _openssl_date(days: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(days=days, hours=1)
    return moment.strftime("%b %d %H:%M:%S %Y GMT")


def _state() -> AppState:
    state = AppState()
    state.network.domain = "naive.example.com"
    state.network.sub_domain = "sub.example.com"
    state.protocols["naive"] = PluginState(
        enabled=True,
        installed=True,
        config={"cert_file": "/certs/naive.pem", "key_file": "/certs/naive.key"},
    )
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "cert_file": "/certs/vless.pem",
            "key_file": "/certs/vless.key",
        },
    )
    state.protocols["snell"] = PluginState(enabled=False, installed=True)
    return state


def test_every_enabled_tls_endpoint_is_collected_once():
    endpoints = collect_domains(_state())

    assert [(owner, domain) for owner, domain, _ in endpoints] == [
        ("naive", "naive.example.com"),
        ("vless", "xhttp.example.com"),
        ("subscriptions", "sub.example.com"),
    ]


def test_disabled_protocol_is_not_audited():
    state = _state()
    state.protocols["vless"].enabled = False

    assert all(
        domain != "xhttp.example.com" for _, domain, _ in collect_domains(state)
    )


@pytest.mark.parametrize(
    ("days", "expected"),
    [(200, "ok"), (30, "expiring"), (5, "expiring"), (-1, "expired")],
)
def test_expiry_classification(days: int, expected: str):
    host = _Host({"/certs/naive.pem": _openssl_date(days)})
    state = AppState()
    state.network.domain = "naive.example.com"
    state.protocols["naive"] = PluginState(
        enabled=True,
        config={"cert_file": "/certs/naive.pem", "key_file": "/certs/naive.key"},
    )

    report = CertificateInspector(host, reader=_Reader()).inspect(state)

    assert [status.status for status in report] == [expected]
    assert report[0].needs_renewal is (expected != "ok")


def test_missing_files_are_reported_without_calling_openssl():
    host = _Host({})
    state = AppState()
    state.network.domain = "naive.example.com"
    state.protocols["naive"] = PluginState(
        enabled=True,
        config={"cert_file": "/certs/gone.pem", "key_file": "/certs/gone.key"},
    )

    report = CertificateInspector(
        host,
        reader=_Reader(present=set()),
    ).inspect(state)

    assert report[0].status == "missing"
    assert "/certs/gone.pem" in report[0].detail
    assert host.commands == []


def test_unreadable_certificate_is_not_reported_as_valid():
    host = _Host({}, openssl=False)
    state = AppState()
    state.network.domain = "naive.example.com"
    state.protocols["naive"] = PluginState(
        enabled=True,
        config={"cert_file": "/certs/naive.pem", "key_file": "/certs/naive.key"},
    )

    report = CertificateInspector(host, reader=_Reader()).inspect(state)

    assert report[0].status == "unreadable"
    assert report[0].days_left is None


def test_audit_never_runs_a_mutating_command():
    host = _Host(
        {
            "/certs/naive.pem": _openssl_date(90),
            "/certs/vless.pem": _openssl_date(90),
        },
    )

    CertificateInspector(host, reader=_Reader()).inspect(_state())

    assert host.commands
    for command in host.commands:
        assert command[:4] == ["openssl", "x509", "-enddate", "-noout"]


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("notAfter=Jun  1 12:00:00 2026 GMT", datetime(2026, 6, 1, 12, tzinfo=timezone.utc)),
        ("notAfter=20260601120000Z", datetime(2026, 6, 1, 12, tzinfo=timezone.utc)),
        ("garbage", None),
        ("notAfter=not a date", None),
    ],
)
def test_not_after_parsing(output: str, expected):
    assert parse_not_after(output) == expected


def test_summary_mentions_the_soonest_expiry():
    statuses = [
        CertificateStatus("naive", "a.example.com", "/a.pem", "ok", days_left=80),
        CertificateStatus("vless", "b.example.com", "/b.pem", "ok", days_left=45),
    ]

    assert "45" in summarize(statuses)
    assert "требуют внимания" in summarize(
        [*statuses, CertificateStatus("x", "c.example.com", "/c.pem", "expired")],
    )


def _cycle(state: AppState, statuses: list[CertificateStatus], *, applied=True):
    logs: list[str] = []
    applies: list[AppState] = []

    def apply_config(latest: AppState) -> bool:
        applies.append(latest)
        return applied

    def update_state(mutator):
        return state, mutator(state)

    operations = SyncOperations(
        protocols=SimpleNamespace(
            notify_user_block=lambda *_: [],
            maintenance_jobs=list,
        ),
        apply_config=apply_config,
        check_traffic_limits=lambda _state: [],
        run_maintenance=lambda *_: [],
        inspect_certificates=lambda _state: statuses,
    )
    ok, message = run_sync_cycle(
        state,
        operations=operations,
        update_state=update_state,
        log=logs.append,
    )
    return ok, message, logs, applies


def test_expiring_certificate_queues_a_renewal_apply():
    state = AppState()
    statuses = [
        CertificateStatus("vless", "x.example.com", "/x.pem", "expiring", days_left=9),
    ]

    ok, _message, logs, applies = _cycle(state, statuses)

    assert ok is True
    assert len(applies) == 1
    assert "sync_config_pending" not in state.install
    assert any("истекает через 9" in line for line in logs)
    assert any("queued a config apply" in line for line in logs)


def test_valid_certificates_do_not_trigger_an_apply():
    state = AppState()
    statuses = [
        CertificateStatus("vless", "x.example.com", "/x.pem", "ok", days_left=70),
    ]

    ok, _message, logs, applies = _cycle(state, statuses)

    assert ok is True
    assert applies == []
    assert any("все действительны" in line for line in logs)
    assert state.install["certificates_report"][0]["days_left"] == 70


def test_audit_runs_at_most_once_a_day():
    state = AppState()
    statuses = [
        CertificateStatus("vless", "x.example.com", "/x.pem", "ok", days_left=70),
    ]

    _cycle(state, statuses)
    checked_at = state.install["certificates_last_check"]
    _ok, _message, logs, _applies = _cycle(state, statuses)

    assert state.install["certificates_last_check"] == checked_at
    assert not any("TLS-сертификаты" in line for line in logs)


def test_stale_check_timestamp_forces_a_new_audit():
    state = AppState()
    state.install["certificates_last_check"] = (
        datetime.now(timezone.utc) - timedelta(days=2)
    ).isoformat()
    statuses = [
        CertificateStatus("vless", "x.example.com", "/x.pem", "ok", days_left=70),
    ]

    _ok, _message, logs, _applies = _cycle(state, statuses)

    assert any("TLS-сертификаты" in line for line in logs)


def test_disabled_certificate_check_is_reported_and_skipped():
    state = AppState()
    state.install["sync_certificates_enabled"] = False

    _ok, _message, logs, _applies = _cycle(state, [])

    assert any("Certificate check is disabled" in line for line in logs)
    assert "certificates_last_check" not in state.install


def test_audit_failure_is_reported_without_stopping_the_cycle():
    state = AppState()
    logs: list[str] = []

    def failing(_state):
        raise RuntimeError("openssl exploded")

    operations = SyncOperations(
        protocols=SimpleNamespace(
            notify_user_block=lambda *_: [],
            maintenance_jobs=list,
        ),
        apply_config=lambda _state: True,
        check_traffic_limits=lambda _state: [],
        run_maintenance=lambda *_: [],
        inspect_certificates=failing,
    )
    ok, message = run_sync_cycle(
        state,
        operations=operations,
        update_state=lambda mutator: (state, mutator(state)),
        log=logs.append,
    )

    assert ok is False
    assert "проверка сертификатов" in message
    assert any("audit failed" in line for line in logs)
