from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from subprocess import CompletedProcess

from hydra.core.host import HostBackend
from hydra.services.headless_creator_infrastructure import (
    HeadlessCreatorInfrastructure,
    extract_vk_join_link,
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


def test_join_link_accepts_vk_path_token_characters_and_official_ru_host() -> None:
    link = "https://vk.ru/call/join/room+token=="

    assert validate_vk_join_link(link) == link
    assert extract_call_hash(link) == "room+token=="


def test_join_link_is_extracted_from_creator_prefixed_output() -> None:
    link = "https://vk.com/call/join/room+token=="

    assert extract_vk_join_link(f"join_link: {link}") == link


def test_join_file_reader_ignores_partial_content_until_link_is_complete(monkeypatch) -> None:
    class ChangingPath:
        values = iter([
            "https://vk.com/call/join/",
            "https://vk.com/call/join/room+token==\n",
        ])

        def read_text(self, *, encoding: str) -> str:
            assert encoding == "utf-8"
            return next(self.values)

    process = Process()
    clock = iter([0.0, 0.1, 0.2])
    monkeypatch.setattr(
        "hydra.services.headless_creator_infrastructure.time.monotonic",
        lambda: next(clock),
    )
    monkeypatch.setattr(
        "hydra.services.headless_creator_infrastructure.time.sleep",
        lambda _seconds: None,
    )

    assert HeadlessCreatorInfrastructure._wait_for_join_file(
        process,
        ChangingPath(),
        timeout=1,
    ) == "https://vk.com/call/join/room+token=="


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
    monkeypatch.setattr(
        runtime,
        "_read_hashes_for",
        lambda generation, *, count=None: [f"n{index}" for index in range(1, count + 1)],
    )
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


def test_qwdtt_rotation_uses_requested_room_count(tmp_path, monkeypatch) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)

    hashes = runtime.refresh_creator_pool(previous=[], count=2)
    runtime.commit_pool(hashes, count=2)

    assert hashes == ["n1", "n2"]
    metadata = json.loads(runtime.pool_state_file.read_text(encoding="utf-8"))
    assert metadata["room_count"] == 2
    restarted = [cmd for cmd in host.commands if "restart" in cmd]
    assert any(any("@b-1.service" in arg for arg in cmd) for cmd in restarted)
    assert any(any("@b-2.service" in arg for arg in cmd) for cmd in restarted)
    assert not any(any("@b-3.service" in arg for arg in cmd) for cmd in restarted)


def test_stop_covers_larger_previous_generation_while_cleanup_is_pending(
    tmp_path,
    monkeypatch,
) -> None:
    runtime, host = _pool_runtime(tmp_path, monkeypatch)
    hashes = runtime.refresh_creator_pool(previous=[], count=2)
    runtime.commit_pool(hashes, count=2)

    ok, _message = runtime.stop_creator_pool()

    assert ok is True
    stopped = [cmd for cmd in host.commands if cmd[:2] == ["systemctl", "stop"]]
    assert any(any("@a-4.service" in arg for arg in cmd) for cmd in stopped)


def test_room_count_accepts_only_unique_valid_room_files(tmp_path) -> None:
    pool = tmp_path / "pool"
    pool.mkdir()
    state_file = pool / "state.json"
    state_file.write_text(json.dumps({"generation": "a"}), encoding="utf-8")
    (pool / "a-1.call.txt").write_text(
        "https://vk.com/call/join/room-1\n",
        encoding="utf-8",
    )
    (pool / "a-2.call.txt").write_text(
        "https://vk.com/call/join/room-2\n",
        encoding="utf-8",
    )
    (pool / "a-3.call.txt").write_text(
        "https://vk.com/call/join/room-2\n",
        encoding="utf-8",
    )
    (pool / "a-4.call.txt").write_text("invalid", encoding="utf-8")
    runtime = HeadlessCreatorInfrastructure(
        HostBackend(),
        pool_dir=pool,
        pool_state_file=state_file,
    )

    assert runtime.count_valid_creator_rooms() == 2
