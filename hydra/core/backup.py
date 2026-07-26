"""Secure archive mechanics driven by a trusted application backup policy."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from hydra.contracts import BackupPolicy, BackupResource
from hydra.core.errors import RestoreError


BACKUP_DIR = Path(os.environ.get("HYDRA_BACKUP_DIR", "/var/backups/hydra"))
RESTORE_ROOT = Path("/")
MANIFEST_NAME = "var/lib/hydra/backup-manifest.json"
CORE_BACKUP_RESOURCES = (
    BackupResource(
        "/var/lib/hydra",
        "tree",
        owner="core",
        excludes=("state.lock", "*.tmp", "*.pending"),
    ),
    BackupResource("/etc/hydra", "tree", owner="core"),
    BackupResource("/etc/sing-box", "tree", owner="sing-box"),
    BackupResource("/etc/caddy-l4", "tree", owner="sni-router"),
    BackupResource("/etc/iptables/rules.v4", "file", owner="firewall"),
    BackupResource("/etc/nftables.conf", "file", owner="firewall"),
    *(
        BackupResource(
            f"/etc/systemd/system/{unit}",
            "file",
            owner="core",
        )
        for unit in (
            "caddy-l4.service",
            "hydra-caddy-source.service",
            "hydra-source-relay.service",
            "hydra-sub.service",
            "hydra-tg-admin.service",
            "hydra-tg-bot.service",
            "hydra-traffic-daemon.service",
            "hydra-sync-agent.service",
            "hydra-sync-agent.timer",
            "sing-box.service",
        )
    ),
)
DEFAULT_BACKUP_POLICY = BackupPolicy(CORE_BACKUP_RESOURCES)


def _policy_or_default(policy: BackupPolicy | None) -> BackupPolicy:
    return policy if policy is not None else DEFAULT_BACKUP_POLICY


def _archive_name() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S%fZ")
    return BACKUP_DIR / f"hydra-backup-{stamp}.tar.gz"


def _archive_path(path: Path) -> str:
    name = path.as_posix().lstrip("/")
    if ":/" in name:  # Test/development paths on Windows.
        name = name.split(":/", 1)[1]
    return name


def _excluded(relative: str, resource: BackupResource) -> bool:
    path = PurePosixPath(relative)
    return any(
        path.match(pattern) or path.name == pattern
        for pattern in resource.excludes
    )


def _resource_files(resource: BackupResource) -> list[Path]:
    root = Path(resource.path)
    if root.is_symlink() or not root.exists():
        return []
    if resource.kind == "file":
        if not root.is_file():
            raise OSError(f"backup resource is not a file: {root}")
        return [root]
    if resource.kind != "tree":
        raise ValueError(f"unsupported backup resource kind: {resource.kind}")
    if not root.is_dir():
        raise OSError(f"backup resource is not a directory: {root}")
    return [
        path
        for path in root.rglob("*")
        if (
            path.is_file()
            and not path.is_symlink()
            and not _excluded(path.relative_to(root).as_posix(), resource)
        )
    ]


def _source_files(
    policy: BackupPolicy,
) -> list[tuple[Path, BackupResource]]:
    by_path: dict[Path, BackupResource] = {}
    for resource in policy.resources:
        for path in _resource_files(resource):
            by_path.setdefault(path, resource)
    return sorted(by_path.items(), key=lambda item: item[0].as_posix())


def _resource_prefix(resource: BackupResource) -> str:
    return _archive_path(Path(resource.path)).rstrip("/")


def _is_allowed_archive_path(
    name: str,
    policy: BackupPolicy,
) -> bool:
    for resource in policy.resources:
        prefix = _resource_prefix(resource)
        if resource.kind == "file":
            if name == prefix:
                return True
            continue
        if name == prefix:
            relative = ""
        elif name.startswith(prefix + "/"):
            relative = name[len(prefix) + 1 :]
        else:
            continue
        return not _excluded(relative, resource)
    return False


def create_backup(
    output: str | Path | None = None,
    *,
    policy: BackupPolicy | None = None,
) -> dict:
    """Create an atomic archive from the current trusted resource inventory."""
    active_policy = _policy_or_default(policy)
    destination = Path(output) if output else _archive_name()
    if destination.exists() and destination.is_dir():
        destination = destination / _archive_name().name
    if destination.exists():
        raise FileExistsError(f"backup already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        destination.parent.chmod(0o700)

    sources = _source_files(active_policy)
    manifest_files: list[dict[str, str | int]] = []
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.tmp",
    )
    try:
        for source, resource in sources:
            manifest_files.append(
                {
                    "path": source.as_posix(),
                    "archive_path": _archive_path(source),
                    "owner": resource.owner,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "bytes": source.stat().st_size,
                },
            )
        manifest = {
            "format": 2,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": manifest_files,
        }
        with tarfile.open(temporary, "w:gz") as archive:
            for source, _resource in sources:
                archive.add(
                    source,
                    arcname=_archive_path(source),
                    recursive=False,
                )
            payload = json.dumps(
                manifest,
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8")
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


def _safe_members(
    archive: tarfile.TarFile,
    policy: BackupPolicy,
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    seen: set[str] = set()
    for member in archive.getmembers():
        raw_name = member.name.replace("\\", "/")
        name = raw_name.strip("/")
        parts = PurePosixPath(name).parts
        if (
            not name
            or raw_name.startswith("/")
            or ".." in parts
            or member.issym()
            or member.islnk()
        ):
            raise RestoreError(f"unsafe backup member: {member.name}")
        if name in seen:
            raise RestoreError(f"duplicate backup member: {name}")
        seen.add(name)
        if (
            name != MANIFEST_NAME
            and not _is_allowed_archive_path(name, policy)
        ):
            raise RestoreError(
                f"backup member is outside HYDRA paths: {member.name}",
            )
        if not member.isfile():
            raise RestoreError(
                f"unsupported backup member type: {member.name}",
            )
        member.name = name
        members.append(member)
    return members


def _read_manifest(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
) -> tuple[dict, dict[str, tarfile.TarInfo]]:
    by_name = {member.name: member for member in members}
    manifest_member = by_name.get(MANIFEST_NAME)
    if manifest_member is None:
        raise RestoreError("backup manifest is missing")
    manifest_handle = archive.extractfile(manifest_member)
    if manifest_handle is None:
        raise RestoreError("backup manifest cannot be read")
    try:
        manifest = json.loads(manifest_handle.read().decode("utf-8"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RestoreError("backup manifest cannot be read") from exc
    if (
        manifest.get("format") != 2
        or not isinstance(manifest.get("files"), list)
    ):
        raise RestoreError("unsupported backup format")
    return manifest, by_name


def _manifest_index(files: list) -> dict[str, dict]:
    expected: dict[str, dict] = {}
    for item in files:
        if not isinstance(item, dict):
            raise RestoreError("backup manifest contains an invalid entry")
        name = item.get("archive_path")
        if not isinstance(name, str) or not name or name in expected:
            raise RestoreError("backup manifest contains duplicate paths")
        expected[name] = item
    return expected


def inspect_backup(
    archive_path: str | Path,
    *,
    policy: BackupPolicy | None = None,
) -> dict:
    """Validate archive structure, authorization, checksums, and state."""
    active_policy = _policy_or_default(policy)
    path = Path(archive_path)
    if not path.is_file():
        raise RestoreError(f"backup not found: {path}")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = _safe_members(archive, active_policy)
            manifest, by_name = _read_manifest(archive, members)
            expected = _manifest_index(manifest["files"])
            payload_names = {
                name for name in by_name if name != MANIFEST_NAME
            }
            if set(expected) != payload_names:
                raise RestoreError(
                    "backup manifest does not match archive contents",
                )
            for name, item in expected.items():
                handle = archive.extractfile(by_name[name])
                if handle is None:
                    raise RestoreError(
                        f"backup member cannot be read: {name}",
                    )
                payload = handle.read()
                if hashlib.sha256(payload).hexdigest() != item.get("sha256"):
                    raise RestoreError(
                        f"backup checksum mismatch: {name}",
                    )
                if item.get("bytes") not in (None, len(payload)):
                    raise RestoreError(f"backup size mismatch: {name}")
                if name == "var/lib/hydra/state.json":
                    from hydra.core.state import _validate_raw_state

                    _validate_raw_state(json.loads(payload.decode("utf-8")))
    except (tarfile.TarError, OSError) as exc:
        raise RestoreError(f"backup archive cannot be read: {exc}") from exc
    return {
        "valid": True,
        "archive": str(path),
        "format": manifest["format"],
        "created_at": manifest.get("created_at", ""),
        "files": sorted(payload_names),
    }


def restore_backup(
    archive_path: str | Path,
    *,
    dry_run: bool = False,
    policy: BackupPolicy | None = None,
) -> dict:
    """Restore authorized files atomically and roll back every written target."""
    active_policy = _policy_or_default(policy)
    plan = inspect_backup(archive_path, policy=active_policy)
    if dry_run:
        return {
            **plan,
            "dry_run": True,
            "changes": len(plan["files"]),
        }

    safety = create_backup(policy=active_policy)
    snapshots: dict[Path, tuple[bytes, int] | None] = {}
    written: list[Path] = []
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = {
                member.name: member
                for member in _safe_members(archive, active_policy)
            }
            for name in plan["files"]:
                target = RESTORE_ROOT / name
                snapshots[target] = (
                    (target.read_bytes(), target.stat().st_mode & 0o777)
                    if target.is_file()
                    else None
                )
                handle = archive.extractfile(members[name])
                if handle is None:
                    raise RestoreError(
                        f"backup member cannot be read: {name}",
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(
                    f".{target.name}.{os.getpid()}.restore",
                )
                try:
                    temporary.write_bytes(handle.read())
                    temporary.chmod(
                        members[name].mode & 0o777 or 0o600,
                    )
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


__all__ = [
    "BACKUP_DIR",
    "CORE_BACKUP_RESOURCES",
    "DEFAULT_BACKUP_POLICY",
    "MANIFEST_NAME",
    "RESTORE_ROOT",
    "create_backup",
    "inspect_backup",
    "restore_backup",
]
