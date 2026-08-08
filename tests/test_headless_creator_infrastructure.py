from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from subprocess import CompletedProcess

from hydra.core.host import HostBackend
from hydra.services.headless_creator_infrastructure import (
    HeadlessCreatorInfrastructure,
    validate_vk_join_link,
)
from hydra.services.headless_creator_pool_infrastructure import extract_call_hash


class Process:
    def __init__(self) -> None:
        self.closed = False

    def poll(self):
        return 0 if self.closed else None

    def terminate(self):
        self.closed = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.closed = True


class CreatorHost(HostBackend):
    def __init__(self) -> None:
        super().__init__()
        self.commands: list[list[str]] = []
        self.process = Process()

    def which(self, executable: str) -> str | None:
        if "headless-vk-creator" in executable:
            return "/usr/local/bin/headless-vk-creator"
        return None

    def run(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        return CompletedProcess(command, 0, stdout="", stderr="")

    def popen(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        Path(command[-1]).write_text(
            "https://vk.com/call/join/native-room\n",
            encoding="utf-8",
        )
        return self.process


def _cookies(path: Path) -> None:
    path.write_text(
        json.dumps({"cookies": [{"name": " remixsid ", "value": " token "}]}),
        encoding="utf-8",
    )


def test_cookie_normalization_uses_canonical_creator_file_shape(tmp_path) -> None:
    cookie_file = tmp_path / "cookies-vk.json"
    _cookies(cookie_file)
    runtime = HeadlessCreatorInfrastructure(HostBackend(), cookies_file=cookie_file)

    assert runtime.validate_credentials() == [{"name": "remixsid", "value": "token"}]
    if os.name != "nt":
        assert stat.S_IMODE(cookie_file.stat().st_mode) == 0o600
    assert json.loads(cookie_file.read_text(encoding="utf-8")) == [
        {"name": "remixsid", "value": "token"},
    ]


def test_native_room_is_created_by_headless_creator_not_singbox(tmp_path) -> None:
    host = CreatorHost()
    cookie_file = tmp_path / "cookies-vk.json"
    _cookies(cookie_file)
    runtime = HeadlessCreatorInfrastructure(
        host,
        cookies_file=cookie_file,
        runtime_dir=tmp_path / "runtime",
    )

    bootstrap = runtime.start_vk_room()

    assert bootstrap.join_link == "https://vk.com/call/join/native-room"
    assert host.commands[0][0] == "/usr/local/bin/headless-vk-creator"
    assert "sing-box" not in " ".join(host.commands[0])
    assert host.commands[0][2] == str(cookie_file)
    runtime.close_vk_room(bootstrap)
    assert host.process.closed is True


def test_join_link_and_hash_validation_are_strict() -> None:
    link = "https://vk.com/call/join/room_token-1"
    assert validate_vk_join_link(link) == link
    assert extract_call_hash(link) == "room_token-1"


def _pool_runtime(tmp_path, monkeypatch):
    host = CreatorHost()
    cookies = tmp_path / "cookies.json"
    _cookies(cookies)
    pool = tmp_path / "pool"
    pool.mkdir()
    state_file = pool / "state.json"
    state_file.write_text(
        json.dumps({"generation": "a", "hashes": ["old1", "old2", "old3", "old4"]}),
        encoding="utf-8",
    )
    runtime = HeadlessCreatorInfrastructure(
        host,
        cookies_file=cookies,
        pool_dir=pool,
        pool_state_file=state_file,
        creator_unit=tmp_path / "creator@.service",
    )
    monkeypatch.setattr(runtime, "_read_hashes_for", lambda generation: ["n1", "n2", "n3", "n4"])
    return runtime, host


def test_qwdtt_rotation_keeps_old_generation_until_commit(tmp_path, monkeypatch) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)
    hashes = runtime.refresh_creator_pool(previous=["old1", "old2", "old3", "old4"])

    assert any("hydra-headless-creator-vk@b-1.service" in cmd for cmd in host.commands)
    assert not any(
        cmd[:2] == ["systemctl", "stop"]
        and "hydra-headless-creator-vk@a-1.service" in cmd
        for cmd in host.commands
    )
    runtime.commit_pool(hashes)
    runtime.finalize_creator_pool()
    assert any(
        cmd[:2] == ["systemctl", "stop"]
        and "hydra-headless-creator-vk@a-1.service" in cmd
        for cmd in host.commands
    )


def test_qwdtt_rotation_rollback_restores_metadata(tmp_path, monkeypatch) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)
    hashes = runtime.refresh_creator_pool(previous=["old1", "old2", "old3", "old4"])
    runtime.commit_pool(hashes)
    runtime.rollback_creator_pool()

    metadata = json.loads(runtime.pool_state_file.read_text(encoding="utf-8"))
    assert metadata["generation"] == "a"
    assert any(
        cmd[:2] == ["systemctl", "stop"]
        and "hydra-headless-creator-vk@b-1.service" in cmd
        for cmd in host.commands
    )
