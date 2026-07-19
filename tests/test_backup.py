from pathlib import Path
import io
import tarfile

import pytest

from hydra.core import backup
from hydra.core.errors import RestoreError


def test_create_backup_contains_manifest_and_state(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.json"
    state_file.write_text('{"version": 2}', encoding="utf-8")
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup, "_state_sources", lambda: (state_file,))
    monkeypatch.setattr(backup, "CONFIG_SOURCES", ())
    monkeypatch.setattr(backup, "_archive_path", lambda path: f"var/lib/hydra/{path.name}")

    result = backup.create_backup()

    archive_path = Path(result["archive"])
    assert result["ok"] is True
    assert result["files"] == 1
    with tarfile.open(archive_path, "r:gz") as archive:
        names = archive.getnames()
    assert "var/lib/hydra/state.json" in names
    assert "var/lib/hydra/backup-manifest.json" in names

    inspection = backup.inspect_backup(archive_path)
    assert inspection["valid"] is True


def test_restore_requires_valid_archive_and_writes_under_restore_root(tmp_path, monkeypatch):
    source = tmp_path / "source-state.json"
    source.write_text('{"version": 2, "users": []}', encoding="utf-8")
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup, "_state_sources", lambda: (source,))
    monkeypatch.setattr(backup, "CONFIG_SOURCES", ())
    monkeypatch.setattr(backup, "_archive_path", lambda path: "var/lib/hydra/state.json")
    created = backup.create_backup()

    restore_root = tmp_path / "restored"
    monkeypatch.setattr(backup, "RESTORE_ROOT", restore_root)
    monkeypatch.setattr(
        backup, "create_backup",
        lambda: {"archive": str(tmp_path / "safety.tar.gz")},
    )
    dry_run = backup.restore_backup(Path(created["archive"]), dry_run=True)
    assert dry_run["changes"] == 1

    result = backup.restore_backup(Path(created["archive"]))
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
        backup.inspect_backup(archive_path)
