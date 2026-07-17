"""
hydra/utils/downloader.py — Скачивание бинарников с GitHub releases.

Логика портирована из legacy vless_installer/modules/naiveproxy.py
(_download_binary, _get_latest_version).
"""
from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def latest_release(repo: str, timeout: int = 10) -> str:
    """Возвращает tag_name (с 'v') последнего релиза. 'unknown' при ошибке.

    repo = 'owner/repo', напр. 'enfein/mieru'.
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "HYDRA-Installer"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("tag_name", "unknown")
    except Exception:
        return "unknown"


def download(url: str, dest: Path, timeout: int = 120) -> bool:
    """Скачивает файл по URL в dest. Возвращает True при успехе."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Скачиваем во временный файл, затем атомарно перемещаем
        fd, tmp = tempfile.mkstemp(dir=str(dest.parent))
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "HYDRA-Installer"})
            with urllib.request.urlopen(request, timeout=timeout) as response, open(tmp, "wb") as output:
                shutil.copyfileobj(response, output)
            shutil.move(tmp, str(dest))
            return True
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            return False
    except Exception:
        return False


def download_github_asset(repo: str, asset_pattern: str, dest: Path) -> bool:
    """Ищет asset по имени (substring) в latest release, скачивает в dest.

    asset_pattern — подстрока имени, напр. 'linux-amd64.deb'.
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "HYDRA-Installer"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())

        for asset in data.get("assets", []):
            if asset_pattern in asset["name"]:
                return download(asset["browser_download_url"], dest)

        return False
    except Exception:
        return False


def download_github_asset_filtered(repo: str, name_filter: callable, dest: Path) -> bool:
    """Скачивает ассет из latest release, фильтруя через callable.

    name_filter принимает имя ассета (str) и возвращает True если подходит.
    Это решает проблему подстрочного поиска: 'linux-amd64.tar.gz' больше
    не матчит 'linux-amd64-compressed.tar.gz'.

    Пример:
        download_github_asset_filtered("owner/repo",
            lambda n: "linux-amd64.tar.gz" in n and "compressed" not in n,
            Path("/tmp/file.tar.gz"))
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HYDRA-Installer"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())

        for asset in data.get("assets", []):
            if name_filter(asset["name"]):
                return download(asset["browser_download_url"], dest)
        return False
    except Exception:
        return False


def verify_elf(path: Path) -> bool:
    """True если первые 4 байта == b'\\x7fELF'."""
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def extract_tarball(archive: Path, dest: Path) -> Path:
    """Safely extract a tar.gz archive inside ``dest``."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(str(archive), "r:gz") as tar:
        destination = dest.resolve()
        members = tar.getmembers()
        for member in members:
            member_path = (destination / member.name).resolve()
            try:
                member_path.relative_to(destination)
            except ValueError as exc:
                raise ValueError(f"Unsafe path in archive: {member.name}") from exc
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"Unsafe archive member: {member.name}")
        tar.extractall(path=str(destination), members=members)
    return dest
