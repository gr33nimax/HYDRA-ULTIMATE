from pathlib import Path
import hashlib
import io
import json
import tarfile

import pytest

from hydra.contracts import BackupPolicy, BackupResource
from hydra.core import backup
from hydra.core.errors import RestoreError


def test_create_backup_contains_manifest_and_state(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.json"
    state_file.write_text('{"version": 2}', encoding="utf-8")
    policy = BackupPolicy(
        (BackupResource(str(state_file), "file", owner="test"),),
    )
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup, "_archive_path", lambda path: f"var/lib/hydra/{path.name}")

    result = backup.create_backup(policy=policy)

    archive_path = Path(result["archive"])
    assert result["ok"] is True
    assert result["files"] == 1
    with tarfile.open(archive_path, "r:gz") as archive:
        names = archive.getnames()
    assert "var/lib/hydra/state.json" in names
    assert "var/lib/hydra/backup-manifest.json" in names

    inspection = backup.inspect_backup(archive_path, policy=policy)
    assert inspection["valid"] is True


def test_restore_requires_valid_archive_and_writes_under_restore_root(tmp_path, monkeypatch):
    source = tmp_path / "source-state.json"
    source.write_text('{"version": 2, "users": []}', encoding="utf-8")
    policy = BackupPolicy(
        (BackupResource(str(source), "file", owner="test"),),
    )
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup, "_archive_path", lambda path: "var/lib/hydra/state.json")
    created = backup.create_backup(policy=policy)

    restore_root = tmp_path / "restored"
    monkeypatch.setattr(backup, "RESTORE_ROOT", restore_root)
    monkeypatch.setattr(
        backup, "create_backup",
        lambda *args, **kwargs: {"archive": str(tmp_path / "safety.tar.gz")},
    )
    dry_run = backup.restore_backup(
        Path(created["archive"]),
        dry_run=True,
        policy=policy,
    )
    assert dry_run["changes"] == 1

    result = backup.restore_backup(
        Path(created["archive"]),
        policy=policy,
    )
    restored = restore_root / "var/lib/hydra/state.json"
    assert result["restored"] == 1
    assert restored.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")


def test_restore_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "malicious.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        payload = b"owned"
        member = tarfile.TarInfo("../../etc/passwd")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(RestoreError, match="unsafe backup member"):
        backup.inspect_backup(
            archive_path,
            policy=BackupPolicy(()),
        )


def _write_manifest_archive(
    path: Path,
    *,
    name: str,
    payload: bytes,
) -> None:
    item = {
        "archive_path": name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }
    manifest = json.dumps(
        {"format": 2, "created_at": "", "files": [item]},
    ).encode()
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
        manifest_member = tarfile.TarInfo(backup.MANIFEST_NAME)
        manifest_member.size = len(manifest)
        archive.addfile(manifest_member, io.BytesIO(manifest))


def test_exact_file_resource_does_not_authorize_siblings(tmp_path, monkeypatch):
    rules = tmp_path / "rules.v4"
    policy = BackupPolicy(
        (BackupResource(str(rules), "file", owner="firewall"),),
    )
    monkeypatch.setattr(
        backup,
        "_archive_path",
        lambda path: f"etc/iptables/{path.name}",
    )
    archive_path = tmp_path / "rules-v6.tar.gz"
    _write_manifest_archive(
        archive_path,
        name="etc/iptables/rules.v6",
        payload=b"*filter\nCOMMIT\n",
    )

    with pytest.raises(RestoreError, match="outside HYDRA paths"):
        backup.inspect_backup(archive_path, policy=policy)


def test_tree_resource_is_recursive_and_excludes_runtime_files(
    tmp_path,
    monkeypatch,
):
    state_dir = tmp_path / "state"
    nested = state_dir / "plugins" / "example"
    nested.mkdir(parents=True)
    (nested / "data.json").write_text("{}", encoding="utf-8")
    (state_dir / "state.lock").write_text("", encoding="utf-8")
    (state_dir / "state.json.1.tmp").write_text("tmp", encoding="utf-8")
    policy = BackupPolicy(
        (
            BackupResource(
                str(state_dir),
                "tree",
                owner="core",
                excludes=("state.lock", "*.tmp"),
            ),
        ),
    )
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(
        backup,
        "_archive_path",
        lambda path: (
            "var/lib/hydra"
            if path == state_dir
            else "var/lib/hydra/"
            + path.relative_to(state_dir).as_posix()
        ),
    )

    created = backup.create_backup(policy=policy)
    inspected = backup.inspect_backup(
        created["archive"],
        policy=policy,
    )

    assert inspected["files"] == [
        "var/lib/hydra/plugins/example/data.json",
    ]
