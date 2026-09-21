"""Telemt binary and systemd unit lifecycle."""

from __future__ import annotations

import platform
import shutil
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

from hydra.utils.commands import bounded_reason
from hydra.utils.downloader import (
    download_github_asset_filtered,
    extract_tarball,
    verify_elf,
)

from .constants import SERVICE_USER
from .upstream_contract import RELEASE_TAG, release_archive


class HostRunner(Protocol):
    """The subset of the injected HostBackend this module drives."""

    def run(
        self,
        args: Sequence[object],
        *,
        timeout: float = ...,
        check: bool = ...,
        text: bool = ...,
        capture_output: bool = ...,
        encoding: str | None = ...,
        errors: str | None = ...,
    ) -> Any: ...

    def atomic_write(self, path: Path, content: str | bytes, *, mode: int = 0o644) -> None: ...

    def ensure_directory(self, path: Path, *, mode: int = 0o755) -> None: ...

    def remove_file(self, path: Path) -> None: ...


def report_stage(on_failure: Callable[[str], None] | None, stage: str) -> None:
    """Report one redacted failure stage without leaking host output."""
    if on_failure is None:
        return
    try:
        on_failure(stage)
    except Exception:
        pass


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def ensure_service_user(host: HostRunner) -> bool:
    present = host.run(["getent", "passwd", SERVICE_USER], capture_output=True)
    if present.returncode == 0:
        return True
    result = host.run(
        [
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
        capture_output=True,
    )
    return result.returncode == 0


def write_service(
    *,
    host: HostRunner,
    work_dir: Path,
    service_file: Path,
    bin_path: Path,
    config_file: Path,
    service_name: str,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Write Telemt's least-privilege systemd unit through HostBackend."""
    host.ensure_directory(work_dir, mode=0o750)
    host.ensure_directory(service_file.parent)
    # The unit runs as the service user, so it must be able to enter and write
    # its working directory: a root-owned 0750 directory fails CHDIR with
    # "status=200/CHDIR".
    ownership = host.run(["chown", f"{SERVICE_USER}:{SERVICE_USER}", str(work_dir)], capture_output=True)
    if ownership.returncode != 0:
        report_stage(on_failure, "не удалось назначить владельца рабочего каталога Telemt")
        return False
    unit = (
        "[Unit]\n"
        "Description=Hydra Telemt MTProxy\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={SERVICE_USER}\n"
        f"Group={SERVICE_USER}\n"
        f"WorkingDirectory={work_dir}\n"
        f"ExecStart={bin_path} {config_file}\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "LimitNOFILE=1048576\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
        "ProtectSystem=full\n"
        f"ReadWritePaths={work_dir}\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    host.atomic_write(service_file, unit, mode=0o644)
    result = host.run(["systemctl", "daemon-reload"], capture_output=True)
    if result.returncode == 0:
        return True
    reason = bounded_reason(result) or "проверьте systemctl daemon-reload на хосте"
    report_stage(on_failure, f"systemd не принял юнит Telemt: {reason}")
    return False


def download_and_extract(
    asset_pattern: str,
    dest: Path,
    archive: Path,
    *,
    repo: str,
    bin_path: Path,
    release_tag: str = RELEASE_TAG,
    download_asset=download_github_asset_filtered,
    extract_archive=extract_tarball,
    verify_binary=verify_elf,
) -> bool:
    if not download_asset(
        repo,
        lambda name: name == asset_pattern,
        archive,
        release_tag=release_tag,
        require_unique=True,
        require_digest=True,
    ):
        return False
    extract_dir = dest / "extracted"
    _remove_tree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        extract_archive(archive, extract_dir)
        found = next(extract_dir.rglob("telemt"), None)
        if found is None or not verify_binary(found):
            return False
        bin_path.parent.mkdir(parents=True, exist_ok=True)
        pending = bin_path.with_suffix(".pending")
        shutil.copy2(found, pending)
        pending.chmod(0o755)
        if not verify_binary(pending):
            pending.unlink(missing_ok=True)
            return False
        pending.replace(bin_path)
        return True
    except (OSError, ValueError):
        return False


def download_binary(*, repo: str, bin_path: Path, release_tag: str = RELEASE_TAG) -> bool:
    machine = platform.machine().lower()
    architecture = "aarch64" if machine in {"aarch64", "arm64"} else "x86_64"
    asset_pattern = release_archive(architecture)
    dest = Path(tempfile.gettempdir()) / "hydra-telemt"
    dest.mkdir(parents=True, exist_ok=True)
    return download_and_extract(
        asset_pattern,
        dest,
        dest / asset_pattern,
        repo=repo,
        bin_path=bin_path,
        release_tag=release_tag,
    )


def update_binary(*, host: Any, repo: str, bin_path: Path, service_name: str) -> bool:
    """Manually install latest stable Telemt and restore it if health fails."""
    from hydra.utils.downloader import latest_release

    release_tag = latest_release(repo)
    if release_tag == "unknown" or not bin_path.exists():
        return False
    previous_binary = bin_path.read_bytes()
    active_result = host.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
    active = not bool(active_result.returncode)
    if not download_binary(repo=repo, bin_path=bin_path, release_tag=release_tag):
        return False
    if not active:
        return True
    restart = host.run(["systemctl", "restart", service_name], capture_output=True)
    healthy = host.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
    if restart.returncode == 0 and healthy.returncode == 0:
        return True
    host.atomic_write(bin_path, previous_binary, mode=0o755)
    host.run(["systemctl", "restart", service_name], capture_output=True)
    return False


def install(
    *,
    host: HostRunner,
    repo: str,
    bin_path: Path,
    work_dir: Path,
    service_file: Path,
    config_file: Path,
    service_name: str,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Install Telemt without leaving a partial binary or unit behind."""
    previous_binary = bin_path.read_bytes() if bin_path.exists() else None
    previous_service = service_file.read_bytes() if service_file.exists() else None
    installed = bool(previous_binary and verify_elf(bin_path))
    success = installed or download_binary(repo=repo, bin_path=bin_path)
    if not success:
        report_stage(on_failure, "не удалось скачать бинарник Telemt")
    elif not ensure_service_user(host):
        success = False
        report_stage(on_failure, "не удалось создать сервисного пользователя Telemt")
    elif not write_service(
        host=host,
        work_dir=work_dir,
        service_file=service_file,
        bin_path=bin_path,
        config_file=config_file,
        service_name=service_name,
        on_failure=on_failure,
    ):
        success = False
        report_stage(on_failure, "не удалось записать systemd-юнит Telemt")
    if success:
        return True
    _restore_file(host, bin_path, previous_binary, mode=0o755)
    _restore_file(host, service_file, previous_service, mode=0o644)
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    return False


def _restore_file(host: HostRunner, path: Path, content: bytes | None, *, mode: int) -> None:
    if content is None:
        host.remove_file(path)
    else:
        host.atomic_write(path, content, mode=mode)


def uninstall(
    *,
    host: HostRunner,
    service_name: str,
    service_file: Path,
    bin_path: Path,
    directories: tuple[Path, ...],
) -> bool:
    host.run(["systemctl", "disable", "--now", service_name], capture_output=True)
    service_file.unlink(missing_ok=True)
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    bin_path.unlink(missing_ok=True)
    for directory in directories:
        _remove_tree(directory)
    return True
