from __future__ import annotations

import io
import json
import os
import stat
from subprocess import CompletedProcess

import pytest

from hydra.core.host import HostBackend
from hydra.services.calls_infrastructure import (
    CallsInfrastructure,
    extract_call_hash,
    validate_join_link,
)


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
    runtime = CallsInfrastructure(host)

    assert runtime.feature_supported() is True
    assert host.commands[0][0:3] == ["/usr/bin/sing-box", "check", "-c"]


def test_feature_probe_blocks_unsupported_singbox() -> None:
    assert CallsInfrastructure(ProbeHost(returncode=1)).feature_supported() is False


def test_feature_probe_normalizes_host_failure_to_unsupported() -> None:
    assert CallsInfrastructure(FailingProbeHost()).feature_supported() is False


def test_cookie_normalization_and_protected_write(tmp_path) -> None:
    cookie_file = tmp_path / "cookies-vk.json"
    cookie_file.write_text(
        json.dumps({"cookies": [{"name": " remixsid ", "value": " token "}]}),
        encoding="utf-8",
    )
    runtime = CallsInfrastructure(HostBackend(), cookies_file=cookie_file)

    assert runtime.validate_credentials() == [{"name": "remixsid", "value": "token"}]
    if os.name != "nt":
        assert stat.S_IMODE(cookie_file.stat().st_mode) == 0o600
    assert json.loads(cookie_file.read_text(encoding="utf-8")) == [
        {"name": "remixsid", "value": "token"},
    ]


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


def test_join_link_and_creator_hash_validation() -> None:
    link = "https://vk.com/call/join/room_token-1"
    assert validate_join_link(link) == link
    assert extract_call_hash(link) == "room_token-1"


class Process:
    def __init__(self, output: str) -> None:
        self.stdout = io.StringIO(output)

    def poll(self):
        return None


def test_bootstrap_output_extracts_only_strict_vk_join_link() -> None:
    process = Process("INFO created https://vk.com/call/join/new-room\n")
    assert CallsInfrastructure._read_process_join_link(process, timeout=1) == (
        "https://vk.com/call/join/new-room"
    )


def test_creator_hashes_require_four_unique_rooms(tmp_path) -> None:
    runtime = CallsInfrastructure(
        HostBackend(),
        pool_dir=tmp_path,
        pool_state_file=tmp_path / "state.json",
    )
    for index, value in enumerate(("one", "two", "three", "four"), start=1):
        (tmp_path / f"{index}.call.txt").write_text(
            f"https://vk.com/call/join/{value}\n",
            encoding="utf-8",
        )
    assert runtime.read_creator_hashes() == ["one", "two", "three", "four"]
    (tmp_path / "4.call.txt").write_text(
        "https://vk.com/call/join/one\n",
        encoding="utf-8",
    )
    assert runtime.read_creator_hashes() == []


def _pool_runtime(tmp_path, monkeypatch):
    host = ProbeHost()
    cookies = tmp_path / "cookies.json"
    cookies.write_text(
        json.dumps([{"name": "remixsid", "value": "secret"}]),
        encoding="utf-8",
    )
    pool = tmp_path / "pool"
    pool.mkdir()
    state_file = pool / "state.json"
    state_file.write_text(
        json.dumps({"generation": "a", "hashes": ["old1", "old2", "old3", "old4"]}),
        encoding="utf-8",
    )
    runtime = CallsInfrastructure(
        host,
        cookies_file=cookies,
        pool_dir=pool,
        pool_state_file=state_file,
        creator_unit=tmp_path / "creator@.service",
    )
    monkeypatch.setattr(
        runtime,
        "_read_hashes_for",
        lambda generation: ["new1", "new2", "new3", "new4"],
    )
    return runtime, host


def test_qwdtt_rotation_keeps_old_generation_until_commit(tmp_path, monkeypatch) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)

    hashes = runtime.refresh_creator_pool(previous=["old1", "old2", "old3", "old4"])

    assert hashes == ["new1", "new2", "new3", "new4"]
    assert any("hydra-vk-call-creator@b-1.service" in command for command in host.commands)
    assert not any(
        command[:2] == ["systemctl", "stop"]
        and "hydra-vk-call-creator@a-1.service" in command
        for command in host.commands
    )
    runtime.commit_pool(hashes)
    runtime.finalize_creator_pool()
    assert any(
        command[:2] == ["systemctl", "stop"]
        and "hydra-vk-call-creator@a-1.service" in command
        for command in host.commands
    )


def test_qwdtt_rotation_rollback_stops_staging_and_restores_metadata(tmp_path, monkeypatch) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)
    hashes = runtime.refresh_creator_pool(previous=["old1", "old2", "old3", "old4"])
    runtime.commit_pool(hashes)

    runtime.rollback_creator_pool()

    metadata = json.loads(runtime.pool_state_file.read_text(encoding="utf-8"))
    assert metadata["generation"] == "a"
    assert any(
        command[:2] == ["systemctl", "stop"]
        and "hydra-vk-call-creator@b-1.service" in command
        for command in host.commands
    )
