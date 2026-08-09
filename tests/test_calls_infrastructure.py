from __future__ import annotations

from subprocess import CompletedProcess
import json

import pytest

from hydra.core.host import HostBackend
from hydra.services.calls_infrastructure import CallsInfrastructure, validate_join_link


class ProbeHost(HostBackend):
    def __init__(self, *, returncode: int = 0) -> None:
        super().__init__()
        self.returncode = returncode
        self.commands: list[list[str]] = []

    def which(self, executable: str) -> str | None:
        return "/usr/bin/sing-box" if executable == "sing-box" else None

    def run(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        return CompletedProcess(command, self.returncode, stdout="", stderr="")


class FailingProbeHost(ProbeHost):
    def run(self, args, **kwargs):
        raise TimeoutError


def test_feature_probe_uses_singbox_check_with_minimal_call_config() -> None:
    host = ProbeHost()
    assert CallsInfrastructure(host).feature_supported() is True
    assert any(command[0:3] == ["/usr/bin/sing-box", "check", "-c"] for command in host.commands)


def test_feature_probe_blocks_unsupported_or_failed_singbox() -> None:
    assert CallsInfrastructure(ProbeHost(returncode=1)).feature_supported() is False
    assert CallsInfrastructure(FailingProbeHost()).feature_supported() is False


@pytest.mark.parametrize(
    "value",
    [
        "https://vk.com/call/join/",
        "http://vk.com/call/join/token",
        "https://evil.example/call/join/token",
        "https://vk.com/call/join/token?leak=1",
    ],
)
def test_join_link_validation_is_strict(value: str) -> None:
    with pytest.raises(ValueError):
        validate_join_link(value)


def test_calls_reads_credentials_only_through_injected_creator(tmp_path) -> None:
    source = type("Source", (), {
        "load_vk_cookies": lambda self: [{"name": "remixsid", "value": "token"}],
    })()
    runtime = CallsInfrastructure(
        HostBackend(),
        credentials_source=source,
        native_join_file=tmp_path / "native.join",
    )

    assert runtime.load_vk_cookies() == [{"name": "remixsid", "value": "token"}]
    runtime.write_native_join_link("https://vk.com/call/join/room-token")
    assert runtime.load_native_join_link() == "https://vk.com/call/join/room-token"


class CapabilityHost(ProbeHost):
    def run(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        return CompletedProcess(
            command,
            0,
            stdout=json.dumps({
                "features": {"call_vk_multi_user": True},
                "protocols": {"call_modes": ["p2p", "multi_user"]},
            }),
            stderr="",
        )


def test_multi_user_support_requires_feature_and_mode_capability() -> None:
    runtime = CallsInfrastructure(CapabilityHost())
    assert runtime.feature_supported() is True
    assert runtime.multi_user_supported() is True


@pytest.mark.parametrize(
    "payload",
    [
        {
            "features": {"call_vk_multiuser": True},
            "protocols": {"call_modes": ["p2p", "multi_user"]},
        },
        {
            "features": {"call_vk_multi_user": True},
            "protocols": {"call_modes": ["multi_user"]},
        },
    ],
)
def test_multi_user_support_rejects_alias_or_incomplete_modes(payload) -> None:
    host = CapabilityHost()
    host.run = lambda args, **kwargs: CompletedProcess(
        args,
        0,
        stdout=json.dumps(payload),
        stderr="",
    )
    assert CallsInfrastructure(host).multi_user_supported() is False
