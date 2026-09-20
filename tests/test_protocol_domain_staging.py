from __future__ import annotations

from hydra.core.state import AppState
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.services.protocol_setup import ProtocolSetupService


class _Certificates:
    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        del domain, config
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
