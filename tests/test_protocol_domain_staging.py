from __future__ import annotations

from hydra.core.state import AppState
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.services.protocol_setup import ProtocolSetupService


class _Certificates:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        del config
        self.calls.append(domain)
        return "/cert.pem", "/key.pem"


def test_protocol_domain_staging_creates_missing_desired_state():
    plugin = MtprotoZigPlugin()
    state = AppState()

    staged = ProtocolSetupService(
        _Certificates(),
        lambda name: plugin if name == "mtproto_zig" else None,
    ).stage_domain(state, "mtproto_zig", "MAX.ru.")

    assert staged == "max.ru"
    assert state.protocols["mtproto_zig"].config == {"domain": "max.ru"}


def test_mtproto_zig_stages_fake_tls_domain_without_requesting_a_certificate():
    plugin = MtprotoZigPlugin()
    certificates = _Certificates()
    setup = ProtocolSetupService(
        certificates,
        lambda name: plugin if name == "mtproto_zig" else None,
    )
    state = AppState()

    setup.stage_domain(state, "mtproto_zig", "max.ru")
    setup.prepare_enable(state, "mtproto_zig")

    assert certificates.calls == []
    assert state.protocols["mtproto_zig"].config["domain"] == "max.ru"
    assert "cert_file" not in state.protocols["mtproto_zig"].config
    assert "key_file" not in state.protocols["mtproto_zig"].config
