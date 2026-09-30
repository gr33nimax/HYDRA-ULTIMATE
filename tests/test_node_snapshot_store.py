import hashlib
import os
import stat
from pathlib import Path

import pytest

from hydra.contracts.node_export import NodeClientExport, NodeClientExportUser
from hydra.core.host import HostBackend
from hydra.services.nodes.snapshot_store import NodeSnapshotStore, SnapshotStoreError


def _export(*, generation: int = 1, include_user: bool = False) -> NodeClientExport:
    users = {"user-1": NodeClientExportUser(uuid="user-1")} if include_user else {}
    return NodeClientExport(node_id="de-1", generation=generation, users=users)


def test_snapshot_store_writes_private_durable_content_and_loads_by_hash(tmp_path):
    class RecordingHost(HostBackend):
        durable: bool = False

        def atomic_write(self, path, content, *, mode=0o644, durable=False):
            self.durable = durable
            super().atomic_write(path, content, mode=mode, durable=durable)

    host = RecordingHost()
    store = NodeSnapshotStore(host=host, root=tmp_path / "exports")
    export = _export()

    reference = store.store(export)

    raw = reference.path.read_bytes()
    assert reference.sha256 == hashlib.sha256(raw).hexdigest()
    assert host.durable is True
    if os.name != "nt":
        assert stat.S_IMODE(reference.path.stat().st_mode) == 0o600
    assert store.load("de-1", 1, reference.sha256) == export


def test_snapshot_store_is_immutable_per_generation(tmp_path):
    store = NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports")
    first = store.store(_export())

    assert store.store(_export()) == first
    with pytest.raises(SnapshotStoreError, match="immutable"):
        store.store(_export(include_user=True))


def test_snapshot_store_rejects_tampered_content(tmp_path):
    store = NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports")
    reference = store.store(_export())
    reference.path.write_text("{}", encoding="utf-8")

    with pytest.raises(SnapshotStoreError, match="digest"):
        store.load("de-1", 1, reference.sha256)


def test_snapshot_store_rejects_oversized_export(tmp_path):
    store = NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports", max_bytes=16)

    with pytest.raises(SnapshotStoreError, match="size limit"):
        store.store(_export(include_user=True))


def test_snapshot_store_rejects_symlink_node_directory(tmp_path, monkeypatch):
    store = NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports")
    store.root.mkdir()
    node_directory = store.root / "de-1"
    original_is_symlink = Path.is_symlink

    def is_symlink(path):
        return path == node_directory or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)

    with pytest.raises(SnapshotStoreError, match="symlink"):
        store.store(_export())
