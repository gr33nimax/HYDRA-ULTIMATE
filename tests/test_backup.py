from pathlib import Path
import tarfile

from hydra.core import backup


def test_create_backup_contains_manifest_and_state(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.json"
    state_file.write_text('{"version": 2}', encoding="utf-8")
    monkeypatch.setattr(backup, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup, "_state_sources", lambda: (state_file,))
    monkeypatch.setattr(backup, "CONFIG_SOURCES", ())

    result = backup.create_backup()

    archive_path = Path(result["archive"])
    assert result["ok"] is True
    assert result["files"] == 1
    with tarfile.open(archive_path, "r:gz") as archive:
        names = archive.getnames()
    expected_name = state_file.as_posix().lstrip("/")
    if ":/" in expected_name:
        expected_name = expected_name.split(":/", 1)[1]
    assert expected_name in names
    assert "var/lib/hydra/backup-manifest.json" in names
