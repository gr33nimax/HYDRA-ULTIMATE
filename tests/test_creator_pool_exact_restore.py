from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock
from typing import cast

from hydra.core.host import HostBackend
from hydra.services.headless_creator_pool_snapshot import (
    CreatorPoolRuntimeSnapshot,
    PoolSnapshotRuntime,
    restore_creator_pool_snapshot,
)


def test_restore_removes_new_owned_files_units_but_keeps_credentials_and_restores_old(tmp_path, monkeypatch):
    host = HostBackend()
    old = tmp_path / "a.json"
    new = tmp_path / "b.json"
    cookies = tmp_path / "cookies.json"
    old.write_text("replaced")
    new.write_text("new secret")
    cookies.write_text("private cookies")
    runtime = SimpleNamespace(
        host=host,
        creator_unit=tmp_path / "creator.service",
        pool_state_file=tmp_path / "pool.json",
        call_files=lambda *, generation, count: [old] if generation == "a" else [new] if generation == "b" else [],
        creator_units=lambda *, generation, count: [f"creator-{generation}"],
    )

    def run(argv):
        active = argv[1] in ("is-active", "is-enabled")
        return CompletedProcess(argv, 0 if not active or argv[-1] == "creator-b" else 3)

    command = Mock(side_effect=run)
    monkeypatch.setattr(host, "run", command)
    snapshot = CreatorPoolRuntimeSnapshot({old: (b"original", 0o600)}, ("creator-a",), ("creator-a",))
    restore_creator_pool_snapshot(cast(PoolSnapshotRuntime, runtime), snapshot, count=4)
    assert old.read_bytes() == b"original"
    assert not new.exists()
    assert cookies.read_text() == "private cookies"
    commands = [call.args[0] for call in command.call_args_list]
    assert ["systemctl", "stop", "creator-b"] in commands
    assert ["systemctl", "disable", "creator-b"] in commands
    assert ["systemctl", "start", "creator-a"] in commands
