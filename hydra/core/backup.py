"""Create portable, permission-restricted HYDRA configuration backups."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path


BACKUP_DIR = Path(os.environ.get("HYDRA_BACKUP_DIR", "/var/backups/hydra"))
CONFIG_SOURCES = (
    Path("/etc/hydra"),
    Path("/etc/sing-box"),
    Path("/etc/caddy-l4"),
    Path("/etc/caddy-naive"),
    Path("/etc/wdtt"),
    Path("/etc/telemt"),
    Path("/etc/systemd/system/caddy-l4.service"),
    Path("/etc/systemd/system/caddy-naive.service"),
    Path("/etc/systemd/system/hydra-traffic-daemon.service"),
    Path("/etc/systemd/system/hydra-sync-agent.service"),
    Path("/etc/systemd/system/hydra-sync-agent.timer"),
    Path("/etc/systemd/system/sing-box.service"),
    Path("/etc/systemd/system/telemt.service"),
    Path("/etc/systemd/system/wdtt.service"),
)


def _state_sources() -> tuple[Path, ...]:
    from hydra.core import state

    if not state.STATE_DIR.exists():
        return ()
    return tuple(
        path for path in state.STATE_DIR.iterdir()
        if path.is_file() and path.name != "state.lock" and ".tmp" not in path.name
    )


def _existing_sources() -> list[Path]:
    sources: list[Path] = []
    for path in (*_state_sources(), *CONFIG_SOURCES):
        if path.exists():
            sources.append(path)
    return sources


def _archive_name() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return BACKUP_DIR / f"hydra-backup-{stamp}.tar.gz"


def create_backup(output: Path | None = None) -> dict:
    """Create an atomic tarball containing state and known service config."""
    destination = Path(output) if output else _archive_name()
    if destination.exists() and destination.is_dir():
        destination = destination / _archive_name().name
    if destination.exists():
        raise FileExistsError(f"backup already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        destination.parent.chmod(0o700)

    sources = _existing_sources()
    manifest_files: list[dict[str, str | int]] = []
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        for source in sources:
            if source.is_file():
                manifest_files.append({
                    "path": source.as_posix(),
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "bytes": source.stat().st_size,
                })
        manifest = {
            "format": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": manifest_files,
        }
        with tarfile.open(temporary, "w:gz") as archive:
            for source in sources:
                archive.add(source, arcname=source.as_posix().lstrip("/"), recursive=True)
            payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            info = tarfile.TarInfo("var/lib/hydra/backup-manifest.json")
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, fileobj=io.BytesIO(payload))
        temporary.replace(destination)
        if os.name != "nt":
            destination.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)

    return {
        "ok": True,
        "archive": str(destination),
        "files": len(manifest_files),
        "bytes": destination.stat().st_size,
    }
