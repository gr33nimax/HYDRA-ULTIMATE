"""TSK-002: установка протокола — два имени и сертификат origin."""
from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.contracts.vless_cdn import DEFAULT_XHTTP_PATH, PROTOCOL_NAME
from hydra.services.vless_cdn_install import (
    certificate_not_after,
    install_protocol,
    pick_local_port,
)


class _Issuer:
    """Выдаватель сертификатов для теста: помнит вызовы и умеет падать."""

    def __init__(self, paths: tuple[str, str] = ("", ""), error: Exception | None = None):
        self.paths = paths
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        self.calls.append((domain, dict(config)))
        if self.error is not None:
            raise self.error
        return self.paths


def _counting_port(port: int = 41234, calls: list[int] | None = None):
    log = calls if calls is not None else []

    def allocate() -> int:
        log.append(port)
        return port

    return allocate, log


def _self_signed(path: Path, not_after: datetime) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example.com")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - timedelta(days=30))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def test_install_writes_state_after_the_certificate_exists(tmp_path):
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    not_after = datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    _self_signed(cert, not_after)
    key.write_text("key", encoding="utf-8")
    issuer = _Issuer((str(cert), str(key)))
    allocate, calls = _counting_port()
    state = AppState()

    outcome = install_protocol(
        state,
        cdn_domain="cdn.example.com",
        origin_host="Origin.Example.com",
        provisioner=issuer,
        port_allocator=allocate,
    )

    assert outcome.ok is True
    assert issuer.calls == [("origin.example.com", {})]
    assert calls == [41234]
    config = state.protocols[PROTOCOL_NAME].config
    assert config["cdn_domain"] == "cdn.example.com"
    assert config["origin_host"] == "origin.example.com"
    assert config["xhttp_path"] == DEFAULT_XHTTP_PATH
    assert config["core_port"] == 41234
    assert config["cert_file"] == str(cert)
    assert config["key_file"] == str(key)
    assert outcome.certificate_until == "2027-01-02 03:04 UTC"

    shown = "\n".join(outcome.lines())
    for expected in ("cdn.example.com", "origin.example.com", DEFAULT_XHTTP_PATH, "41234", "2027-01-02"):
        assert expected in shown


def test_install_refuses_bad_input_without_touching_anything():
    state = AppState()
    issuer = _Issuer()

    for cdn, origin, expected in (
        ("", "origin.example.com", "CDN-домен"),
        ("https://cdn.example.com", "origin.example.com", "CDN-домен"),
        ("cdn.example.com/path", "origin.example.com", "CDN-домен"),
        ("cdn.example.com", "localhost", "Origin-имя"),
        ("cdn.example.com", "origin.example.com", "путь"),
    ):
        # Четвёртый случай проверяет путь через отдельный аргумент ниже; здесь он
        # только для полноты таблицы имён, поэтому путь не передаётся, а ожидание
        # относится к имени.
        path = "/assets/logo.png" if expected == "путь" else None
        outcome = install_protocol(
            state,
            cdn_domain=cdn,
            origin_host=origin,
            xhttp_path=path,
            provisioner=issuer,
            port_allocator=_counting_port()[0],
        )
        assert outcome.ok is False
        assert expected in outcome.detail
        assert state.protocols.get(PROTOCOL_NAME) is None

    assert issuer.calls == []


def test_install_refuses_an_invalid_path_before_asking_for_a_certificate():
    state = AppState()
    issuer = _Issuer()

    outcome = install_protocol(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
        xhttp_path="/assets/logo.png",
        provisioner=issuer,
        port_allocator=_counting_port()[0],
    )

    assert outcome.ok is False
    assert issuer.calls == []
    assert state.protocols.get(PROTOCOL_NAME) is None


def test_install_refuses_two_identical_names():
    state = AppState()
    issuer = _Issuer()

    outcome = install_protocol(
        state,
        cdn_domain="same.example.com",
        origin_host="same.example.com",
        provisioner=issuer,
        port_allocator=_counting_port()[0],
    )

    assert outcome.ok is False
    assert issuer.calls == []


def test_certificate_failure_leaves_the_state_untouched():
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(config={"origin_host": "old.example.com"})
    issuer = _Issuer(error=RuntimeError("certbot упал"))

    outcome = install_protocol(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
        provisioner=issuer,
        port_allocator=_counting_port()[0],
    )

    assert outcome.ok is False
    assert "Сертификат origin не выпущен" in outcome.detail
    config = state.protocols[PROTOCOL_NAME].config
    assert config == {"origin_host": "old.example.com"}
    assert "cert_file" not in config
    assert "cdn_domain" not in config


def test_reinstall_keeps_the_port_the_route_already_uses():
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(config={"core_port": 51111})

    def must_not_be_called() -> int:
        raise AssertionError("порт не должен пересчитываться")

    outcome = install_protocol(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
        provisioner=_Issuer(("cert.pem", "key.pem")),
        port_allocator=must_not_be_called,
    )

    assert outcome.ok is True
    assert outcome.core_port == 51111
    assert state.protocols[PROTOCOL_NAME].config["core_port"] == 51111


def test_a_port_that_cannot_be_allocated_stops_the_install():
    state = AppState()

    def failing_allocator() -> int:
        raise RuntimeError("Не удалось подобрать свободный порт: нет сокетов")

    outcome = install_protocol(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
        provisioner=_Issuer(("cert.pem", "key.pem")),
        port_allocator=failing_allocator,
    )

    assert outcome.ok is False
    assert "свободный порт" in outcome.detail
    assert state.protocols.get(PROTOCOL_NAME) is None


def test_certificate_expiry_is_read_or_reported_as_unreadable(tmp_path):
    assert certificate_not_after("") == ""
    assert certificate_not_after(str(tmp_path / "missing.pem")) == ""

    broken = tmp_path / "broken.pem"
    broken.write_text("не сертификат", encoding="utf-8")
    assert certificate_not_after(str(broken)) == ""


def test_pick_local_port_returns_a_port_that_can_be_bound():
    port = pick_local_port()

    assert 1 <= port <= 65535
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))


def test_outcome_shows_a_single_reason_when_it_fails():
    outcome = install_protocol(
        AppState(),
        cdn_domain="",
        origin_host="origin.example.com",
        provisioner=_Issuer(),
        port_allocator=_counting_port()[0],
    )

    assert outcome.lines() == [outcome.detail]
    assert "CDN-домен" in outcome.detail
