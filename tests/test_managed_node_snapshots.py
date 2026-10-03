from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_format import UnsupportedStateVersion
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.snapshots import ManagedNodeSnapshotStore


class RecordingHost(HostBackend):
    def __init__(self) -> None:
        super().__init__()
        self.writes: list[tuple[Path, int, bool]] = []
        self.directories: list[Path] = []

    def atomic_write(self, path, content, *, mode=0o644, durable=False) -> None:
        self.writes.append((path, mode, durable))
        super().atomic_write(path, content, mode=mode, durable=durable)

    def ensure_directory(self, path, *, mode=0o755) -> None:
        self.directories.append(path)
        super().ensure_directory(path, mode=mode)


def _symlink_factory(monkeypatch):
    simulated: set[Path] = set()
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path in simulated or real_is_symlink(path))

    def create(link: Path, target: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
                raise
            simulated.add(link)

    return create


def test_snapshot_reads_reject_symlinked_root_and_file_without_host_mutation(tmp_path: Path, monkeypatch):
    create_symlink = _symlink_factory(monkeypatch)
    host = RecordingHost()
    external = tmp_path / "external"
    external.mkdir()
    linked_root = tmp_path / "snapshot-link"
    create_symlink(linked_root, external, directory=True)
    linked_store = ManagedNodeSnapshotStore(host=host, root=linked_root)
    with pytest.raises(ValueError, match="unsafe"):
        linked_store.load("apply-1")
    assert host.writes == []
    assert host.directories == []

    root = tmp_path / "snapshots"
    root.mkdir()
    target = tmp_path / "outside.json"
    target.write_bytes(b"not a state snapshot")
    create_symlink(root / "apply-1.json", target)
    store = ManagedNodeSnapshotStore(host=host, root=root)
    with pytest.raises(ValueError, match="unsafe"):
        store.load("apply-1")
    assert host.writes == []
    assert host.directories == []


def test_snapshot_save_is_durable_immutable_and_roundtrips(tmp_path: Path):
    host = RecordingHost()
    store = ManagedNodeSnapshotStore(host=host, root=tmp_path / "snapshots")
    state = AppState()
    store.save("apply-1", state)

    path = tmp_path / "snapshots" / "apply-1.json"
    assert store.load("apply-1") == state
    assert host.writes == [(path, 0o600, True)]

    store.save("apply-1", state)
    assert len(host.writes) == 1
    changed = AppState()
    changed.network.domain = "changed.example"
    with pytest.raises(ValueError, match="immutable"):
        store.save("apply-1", changed)
    assert store.load("apply-1") == state


def test_snapshot_size_and_future_format_are_rejected(tmp_path: Path):
    host = RecordingHost()
    store = ManagedNodeSnapshotStore(host=host, root=tmp_path / "snapshots")
    oversized = AppState(install={"payload": "x" * (16 * 1024 * 1024)})
    with pytest.raises(ValueError, match="size limit"):
        store.save("large", oversized)
    assert not (tmp_path / "snapshots").exists()

    store.save("apply-1", AppState())
    path = tmp_path / "snapshots" / "apply-1.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["snapshot_format_version"] = 999
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(UnsupportedStateVersion):
        store.load("apply-1")


def test_snapshot_load_rejects_tampered_state_payload(tmp_path: Path):
    host = RecordingHost()
    store = ManagedNodeSnapshotStore(host=host, root=tmp_path / "snapshots")
    store.save("apply-1", AppState())
    path = tmp_path / "snapshots" / "apply-1.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["state"]["core"]["network"]["domain"] = "tampered.example"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="checksum"):
        store.load("apply-1")


def test_snapshot_load_rejects_unchecksummed_state_envelope(tmp_path: Path):
    host = RecordingHost()
    store = ManagedNodeSnapshotStore(host=host, root=tmp_path / "snapshots")
    state = AppState()
    store.save("apply-1", state)
    path = tmp_path / "snapshots" / "apply-1.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(document["state"]), encoding="utf-8")

    with pytest.raises(ValueError, match="checksum envelope is missing"):
        store.load("apply-1")


def test_snapshot_load_rejects_oversized_file(tmp_path: Path):
    root = tmp_path / "snapshots"
    root.mkdir()
    (root / "apply-1.json").write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    store = ManagedNodeSnapshotStore(host=HostBackend(), root=root)
    with pytest.raises(ValueError, match="size limit"):
        store.load("apply-1")
