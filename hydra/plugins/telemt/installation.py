"""Telemt binary and systemd unit lifecycle."""
from __future__ import annotations

import platform
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from hydra.utils.downloader import (
    download_github_asset,
    extract_tarball,
    latest_release,
    verify_elf,
)


class HostRunner(Protocol):
    def run(self, command: list[str], **kwargs): ...


def write_service(
    *,
    host: HostRunner,
    work_dir: Path,
    service_file: Path,
    bin_path: Path,
    config_file: Path,
    service_name: str,
) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    service_file.write_text(
        "[Unit]\n"
        "Description=Telemt MTProxy Server\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        f"WorkingDirectory={work_dir}\n"
        f"ExecStart={bin_path} {config_file}\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=10\n"
        "LimitNOFILE=1048576\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    host.run(["systemctl", "enable", service_name], capture_output=True)


def download_and_extract(
    asset_pattern: str,
    dest: Path,
    archive: Path,
    *,
    repo: str,
    bin_path: Path,
    download_asset=download_github_asset,
    extract_archive=extract_tarball,
    verify_binary=verify_elf,
) -> bool:
    if not download_asset(repo, asset_pattern, archive):
        print(f"  Не удалось скачать {asset_pattern}")
        return False
    extract_dir = dest / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        extract_archive(archive, extract_dir)
        found = list(extract_dir.rglob("telemt"))
        if not found:
            print("  Бинарник telemt не найден в архиве")
            return False
        bin_path.unlink(missing_ok=True)
        shutil.copy2(str(found[0]), str(bin_path))
        bin_path.chmod(0o755)
        if not verify_binary(bin_path):
            print("  Скачанный файл не является ELF-бинарником")
            return False
        print(f"  telemt установлен: {bin_path}")
        return True
    except Exception as exc:
        print(f"  Ошибка распаковки: {exc}")
        return False


def download_binary(*, repo: str, bin_path: Path) -> bool:
    arch = (
        "aarch64"
        if platform.machine().lower() in ("aarch64", "arm64")
        else "x86_64"
    )
    asset_pattern = f"telemt-{arch}-linux-gnu.tar.gz"
    dest = Path(tempfile.gettempdir()) / "telemt-install"
    dest.mkdir(parents=True, exist_ok=True)
    if latest_release(repo) == "unknown":
        return False
    return download_and_extract(
        asset_pattern,
        dest,
        dest / asset_pattern,
        repo=repo,
        bin_path=bin_path,
    )


def uninstall(
    *,
    host: HostRunner,
    service_name: str,
    service_file: Path,
    bin_path: Path,
    directories: tuple[Path, ...],
) -> bool:
    host.run(["systemctl", "stop", service_name], capture_output=True)
    host.run(["systemctl", "disable", service_name], capture_output=True)
    service_file.unlink(missing_ok=True)
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    host.run(["systemctl", "reset-failed"], capture_output=True)
    bin_path.unlink(missing_ok=True)
    for directory in directories:
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
    return True
