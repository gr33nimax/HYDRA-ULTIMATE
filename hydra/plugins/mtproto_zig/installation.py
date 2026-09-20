"""Install only Hydra-owned mtproto.zig artifacts."""

from __future__ import annotations

import platform
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hydra.utils.downloader import download_github_asset, extract_tarball, verify_elf

from .constants import SERVICE_USER


def _report(on_failure: Callable[[str], None] | None, stage: str) -> None:
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


def ensure_service_user(host: Any) -> bool:
    present = host.run(["getent", "passwd", SERVICE_USER], capture_output=True)
    if present.returncode == 0:
        return True
    return (
        host.run(
            ["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", SERVICE_USER],
            capture_output=True,
        ).returncode
        == 0
    )


def write_service(*, host: Any, service_file: Path, binary: Path, config: Path, work_dir: Path, service: str) -> bool:
    service_file.parent.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    service_file.write_text(
        "[Unit]\nDescription=Hydra MTProto Zig\nAfter=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"User={SERVICE_USER}\nGroup={SERVICE_USER}\nWorkingDirectory={work_dir}\n"
        f"ExecStart={binary} {config}\nRestart=on-failure\nRestartSec=2\nLimitNOFILE=1048576\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=full\n"
        f"ReadWritePaths={work_dir}\n\n[Install]\nWantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    return host.run(["systemctl", "daemon-reload"], capture_output=True).returncode == 0


def download_binary(
    *,
    host: Any,
    repo: str,
    binary: Path,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    machine = platform.machine().lower()
    patterns = (
        ("mtproto-proxy-linux-aarch64_crypto.tar.gz", "mtproto-proxy-linux-aarch64.tar.gz")
        if machine in {"aarch64", "arm64"}
        else ("mtproto-proxy-linux-x86_64_v3.tar.gz", "mtproto-proxy-linux-x86_64.tar.gz")
    )
    destination = Path(tempfile.gettempdir()) / "hydra-mtproto-zig"
    destination.mkdir(parents=True, exist_ok=True)
    reason = "не удалось скачать релизный архив mtproto.zig"
    for pattern in patterns:
        archive = destination / f"{pattern}.tar.gz"
        if not download_github_asset(repo, pattern, archive):
            continue
        extracted = destination / "extracted"
        _remove_tree(extracted)
        try:
            extract_tarball(archive, extracted)
            found = next(
                (
                    item
                    for item in extracted.rglob("*")
                    if item.is_file() and item.name in {"mtproto-proxy", "mtproto-zig"}
                ),
                None,
            )
            if found is None:
                continue
            binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(found, binary)
            binary.chmod(0o755)
            if verify_elf(binary):
                return True
            reason = "загруженный бинарник mtproto.zig не является исполняемым ELF"
        except (OSError, ValueError):
            continue
    _report(on_failure, reason)
    return False


def uninstall(*, host: Any, service: str, service_file: Path, binary: Path, directories: tuple[Path, ...]) -> bool:
    host.run(["systemctl", "disable", "--now", service], capture_output=True)
    service_file.unlink(missing_ok=True)
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    binary.unlink(missing_ok=True)
    for directory in directories:
        _remove_tree(directory)
    return True
