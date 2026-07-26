from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import PluginMeta
from hydra.services.certificates import CertificateProvisioner
from hydra.services.protocol_setup import (
    ProtocolSetupService,
    normalize_protocol_config,
    normalize_required_domain,
)


def _plugin_lookup(
    *,
    tls_domain_source: str = "",
    config_defaults: tuple[tuple[str, object], ...] = (),
):
    plugin = SimpleNamespace(
        meta=PluginMeta(
            "test",
            "test",
            tls_domain_source=tls_domain_source,
            config_defaults=config_defaults,
        ),
    )
    return lambda _name: plugin


class _Host:
    def __init__(self, *, certbot_error: bool = False):
        self.certbot_error = certbot_error
        self.calls = []

    def which(self, executable):
        return f"/usr/bin/{executable}"

    def run(self, command, **kwargs):
        self.calls.append(list(command))
        if command[:3] == ["systemctl", "is-active", "caddy-l4"]:
            return SimpleNamespace(returncode=0, stdout="active\n", stderr="")
        if command and command[0] == "certbot" and self.certbot_error:
            raise OSError("certbot failed")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_explicit_existing_tls_paths_are_reused(tmp_path):
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    host = _Host()

    assert CertificateProvisioner(host).ensure(
        "vpn.example.com",
        {"cert_file": str(cert), "key_file": str(key)},
    ) == (str(cert), str(key))
    assert host.calls == []


def test_certbot_failure_restores_every_service_that_was_stopped():
    host = _Host(certbot_error=True)
    provisioner = CertificateProvisioner(host)

    with patch(
        "hydra.services.certificates.temporary_open_port",
        return_value=nullcontext(),
    ):
        assert provisioner._obtain("vpn.example.com") is False

    assert ["systemctl", "stop", "caddy-l4"] in host.calls
    assert ["systemctl", "start", "caddy-l4"] in host.calls


def test_protocol_setup_updates_only_desired_tls_material():
    calls = []
    certificates = SimpleNamespace(
        ensure=lambda domain, config: calls.append((domain, dict(config)))
        or ("/cert.pem", "/key.pem"),
    )
    state = AppState(
        protocols={
            "hysteria2": PluginState(config={"domain": "VPN.Example.COM."}),
        },
    )

    ProtocolSetupService(
        certificates,
        _plugin_lookup(tls_domain_source="protocol"),
    ).prepare_enable(state, "hysteria2")

    assert calls == [("vpn.example.com", {"domain": "VPN.Example.COM."})]
    assert state.protocols["hysteria2"].config == {
        "domain": "vpn.example.com",
        "cert_file": "/cert.pem",
        "key_file": "/key.pem",
    }


def test_protocol_defaults_are_normalized_without_mutating_input():
    source = {"options": {"values": []}}

    naive = normalize_protocol_config(source, (("network", "tcp"),))
    trusttunnel = normalize_protocol_config(
        source,
        (("transport", "tcp"),),
    )
    naive["options"]["values"].append("changed")

    assert naive["network"] == "tcp"
    assert trusttunnel["transport"] == "tcp"
    assert source == {"options": {"values": []}}


def test_required_domain_normalization_is_shared_with_interactive_adapters():
    assert normalize_required_domain(" VPN.Example.COM. ") == "vpn.example.com"
    with pytest.raises(ValueError, match="Некорректный домен"):
        normalize_required_domain("https://vpn.example.com")


def test_protocol_setup_persists_naive_default_before_lifecycle_hook():
    state = AppState(
        protocols={"naive": PluginState()},
    )
    state.network.domain = "vpn.example.com"
    certificates = SimpleNamespace(
        ensure=lambda domain, config: ("/cert.pem", "/key.pem"),
    )

    ProtocolSetupService(
        certificates,
        _plugin_lookup(
            tls_domain_source="network",
            config_defaults=(("network", "tcp"),),
        ),
    ).prepare_enable(state, "naive")

    assert state.protocols["naive"].config == {
        "network": "tcp",
        "cert_file": "/cert.pem",
        "key_file": "/key.pem",
    }


def test_protocol_setup_rejects_missing_domain_without_host_actions():
    state = AppState(protocols={"anytls": PluginState()})
    certificates = SimpleNamespace(ensure=lambda domain, config: pytest.fail())

    with pytest.raises(ValueError, match="домен"):
        ProtocolSetupService(
            certificates,
            _plugin_lookup(tls_domain_source="protocol"),
        ).prepare_enable(state, "anytls")
