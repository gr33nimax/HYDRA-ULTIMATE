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


def test_calls_can_remove_a_stale_legacy_join_file(tmp_path) -> None:
    legacy = tmp_path / "native.join"
    legacy.write_text("stale", encoding="utf-8")
    runtime = CallsInfrastructure(HostBackend(), native_join_file=legacy)

    runtime.remove_native_join_link()

    assert not legacy.exists()


def test_legacy_credentials_constructor_slot_is_ignored() -> None:
    credentials = object()
    runtime = CallsInfrastructure(HostBackend(), credentials)

    assert runtime.credentials_source is credentials
    assert not hasattr(runtime, "load_vk_cookies")


class CapabilityHost(ProbeHost):
    def run(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        return CompletedProcess(
            command,
            0,
            stdout=json.dumps({
                "identity": {
                    "core_id": "io.hydrabox.hydracore",
                    "role": "vps",
                },
                "features": {
                    "call_vk_multi_user": True,
                    "call_vk_adaptive_multipath": True,
                    "call_vk_multi_user_client": False,
                    "call_vk_multi_user_server": True,
                },
                "protocols": {
                    "call_modes": ["multi_user"],
                    "call_vk_multi_user_wire": {"min": 1, "max": 2},
                },
            }),
            stderr="",
        )


def test_multi_user_support_requires_feature_and_mode_capability() -> None:
    runtime = CallsInfrastructure(CapabilityHost())
    assert runtime.multi_user_supported() is True


@pytest.mark.parametrize(
    "payload",
    [
        {
            "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
            "features": {"call_vk_multiuser": True},
            "protocols": {"call_modes": ["multi_user"]},
        },
        {
            "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
            "features": {
                "call_vk_multi_user": True,
                "call_vk_multi_user_server": True,
                "call_vk_multi_user_client": False,
            },
            "protocols": {"call_modes": ["p2p"]},
        },
        {
            "identity": {"core_id": "third.party.core"},
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
