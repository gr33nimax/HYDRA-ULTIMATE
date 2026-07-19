"""Create portable, permission-restricted HYDRA configuration backups."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from hydra.core.errors import RestoreError


BACKUP_DIR = Path(os.environ.get("HYDRA_BACKUP_DIR", "/var/backups/hydra"))
RESTORE_ROOT = Path("/")
MANIFEST_NAME = "var/lib/hydra/backup-manifest.json"
CONFIG_SOURCES = (
    Path("/etc/hydra"),
    Path("/etc/sing-box"),
    Path("/etc/caddy-l4"),
    Path("/etc/caddy-naive"),
    Path("/etc/wdtt"),
    Path("/etc/telemt"),
    Path("/etc/dnscrypt-proxy"),
    Path("/etc/fail2ban"),
    Path("/etc/iptables/rules.v4"),
    Path("/etc/nftables.conf"),
    Path("/etc/systemd/system/caddy-l4.service"),
    Path("/etc/systemd/system/caddy-naive.service"),
    Path("/etc/systemd/system/hydra-traffic-daemon.service"),
    Path("/etc/systemd/system/hydra-sync-agent.service"),
    Path("/etc/systemd/system/hydra-sync-agent.timer"),
    Path("/etc/systemd/system/sing-box.service"),
    Path("/etc/systemd/system/telemt.service"),
    Path("/etc/systemd/system/wdtt.service"),
)
ALLOWED_DIRECTORY_PREFIXES = (
    "var/lib/hydra",
    "etc/hydra",
    "etc/sing-box",
    "etc/caddy-l4",
    "etc/caddy-naive",
    "etc/wdtt",
    "etc/telemt",
    "etc/dnscrypt-proxy",
    "etc/fail2ban",
    "etc/iptables",
)
ALLOWED_SYSTEMD_FILES = frozenset(
    path.as_posix().lstrip("/") for path in CONFIG_SOURCES
    if path.as_posix().startswith("/etc/systemd/system/")
)
ALLOWED_FILE_PATHS = frozenset({"etc/nftables.conf"})


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
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S%fZ")
    return BACKUP_DIR / f"hydra-backup-{stamp}.tar.gz"


def _source_files(sources: list[Path]) -> list[Path]:
    files: list[Path] = []
    for source in sources:
        if source.is_symlink():
            continue
        if source.is_file():
            files.append(source)
        elif source.is_dir():
            files.extend(
                path for path in source.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
    return sorted(set(files), key=lambda path: path.as_posix())


def _archive_path(path: Path) -> str:
    name = path.as_posix().lstrip("/")
    if ":/" in name:  # Test/development paths on Windows.
        name = name.split(":/", 1)[1]
    return name


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
    files = _source_files(sources)
    manifest_files: list[dict[str, str | int]] = []
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        for source in files:
            manifest_files.append({
                "path": source.as_posix(),
                "archive_path": _archive_path(source),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "bytes": source.stat().st_size,
            })
        manifest = {
            "format": 2,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": manifest_files,
        }
        with tarfile.open(temporary, "w:gz") as archive:
            for source in files:
                archive.add(source, arcname=_archive_path(source), recursive=False)
            payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            info = tarfile.TarInfo(MANIFEST_NAME)
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


def _is_allowed_archive_path(name: str) -> bool:
    if name in ALLOWED_SYSTEMD_FILES or name in ALLOWED_FILE_PATHS:
        return True
    return any(name == prefix or name.startswith(prefix + "/") for prefix in ALLOWED_DIRECTORY_PREFIXES)


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        raw_name = member.name.replace("\\", "/")
        name = raw_name.strip("/")
        parts = PurePosixPath(name).parts
        if not name or raw_name.startswith("/") or ".." in parts or member.issym() or member.islnk():
            raise RestoreError(f"unsafe backup member: {member.name}")
        if name != MANIFEST_NAME and not _is_allowed_archive_path(name):
            raise RestoreError(f"backup member is outside HYDRA paths: {member.name}")
        if not member.isfile():
            raise RestoreError(f"unsupported backup member type: {member.name}")
        member.name = name
        members.append(member)
    return members


def inspect_backup(archive_path: Path) -> dict:
    """Validate archive structure, checksums and the persisted state payload."""
    path = Path(archive_path)
    if not path.is_file():
        raise RestoreError(f"backup not found: {path}")
    with tarfile.open(path, "r:gz") as archive:
        members = _safe_members(archive)
        by_name = {member.name: member for member in members}
        manifest_member = by_name.get(MANIFEST_NAME)
        if manifest_member is None:
            raise RestoreError("backup manifest is missing")
        manifest_handle = archive.extractfile(manifest_member)
        if manifest_handle is None:
            raise RestoreError("backup manifest cannot be read")
        manifest = json.loads(manifest_handle.read().decode("utf-8"))
        if manifest.get("format") != 2 or not isinstance(manifest.get("files"), list):
            raise RestoreError("unsupported backup format")
        expected = {item.get("archive_path"): item for item in manifest["files"]}
        payload_names = {name for name in by_name if name != MANIFEST_NAME}
        if set(expected) != payload_names:
            raise RestoreError("backup manifest does not match archive contents")
        for name, item in expected.items():
            handle = archive.extractfile(by_name[name])
            if handle is None:
                raise RestoreError(f"backup member cannot be read: {name}")
            payload = handle.read()
            if hashlib.sha256(payload).hexdigest() != item.get("sha256"):
                raise RestoreError(f"backup checksum mismatch: {name}")
            if name == "var/lib/hydra/state.json":
                from hydra.core.state import _validate_raw_state
                _validate_raw_state(json.loads(payload.decode("utf-8")))
    return {
        "valid": True,
        "archive": str(path),
        "format": manifest["format"],
        "created_at": manifest.get("created_at", ""),
        "files": sorted(payload_names),
    }


def restore_backup(archive_path: Path, *, dry_run: bool = False) -> dict:
    """Restore validated files atomically without silently deleting newer files."""
    plan = inspect_backup(archive_path)
    if dry_run:
        return {**plan, "dry_run": True, "changes": len(plan["files"])}

    safety = create_backup()
    snapshots: dict[Path, tuple[bytes, int] | None] = {}
    written: list[Path] = []
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = {member.name: member for member in _safe_members(archive)}
            for name in plan["files"]:
                target = RESTORE_ROOT / name
                snapshots[target] = (
                    (target.read_bytes(), target.stat().st_mode & 0o777)
                    if target.is_file() else None
                )
                handle = archive.extractfile(members[name])
                if handle is None:
                    raise RestoreError(f"backup member cannot be read: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(f".{target.name}.{os.getpid()}.restore")
                try:
                    temporary.write_bytes(handle.read())
                    temporary.chmod(members[name].mode & 0o777 or 0o600)
                    temporary.replace(target)
                    written.append(target)
                finally:
                    temporary.unlink(missing_ok=True)
    except Exception:
        for target in reversed(written):
            previous = snapshots[target]
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                content, mode = previous
                target.write_bytes(content)
                target.chmod(mode)
        raise
    return {
        "ok": True,
        "archive": str(archive_path),
        "restored": len(written),
        "safety_backup": safety["archive"],
        "next_step": "sudo hydra validate && sudo hydra apply",
    }
