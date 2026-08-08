"""Host adapter for the standalone, provider-neutral headless creator."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hydra.core.host import HostBackend
from hydra.services.headless_creator_pool_infrastructure import (
    CREATOR_BINARY,
    CREATOR_COUNT,
    CREATOR_REPO,
    CREATOR_UNIT,
    QWDTT_POOL_DIR,
    QWDTT_POOL_STATE,
    CreatorPoolStage,
    HeadlessCreatorPoolInfrastructureMixin,
)


CREATOR_CONFIG_DIR = Path("/etc/hydra/cookiesvk")
VK_COOKIES_FILE = CREATOR_CONFIG_DIR / "cookies-vk.json"
CREATOR_RUNTIME_DIR = Path("/var/lib/hydra/headless-creator")
_JOIN_RE = re.compile(r"https://vk\.com/call/join/[A-Za-z0-9._~-]+")


@dataclass(frozen=True)
class CreatorBootstrap:
    process: Any
    directory: Path
    join_link: str


def normalize_vk_cookies(value: object) -> list[dict[str, str]]:
    """Return the minimal cookie shape consumed by both creator and Sing-Box."""
    if isinstance(value, dict):
        value = value.get("cookies", [value])
    if not isinstance(value, list) or not value:
        raise ValueError("VK cookies JSON must contain a non-empty list")
    cookies: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError("invalid VK cookie entry")
        name = str(entry.get("name", "")).strip()
        cookie_value = str(entry.get("value", "")).strip()
        if not name or not cookie_value:
            raise ValueError("VK cookie name and value must be non-empty")
        cookies.append({"name": name, "value": cookie_value})
    return cookies


def validate_vk_join_link(value: str) -> str:
    link = str(value or "").strip()
    match = _JOIN_RE.fullmatch(link)
    if match is None:
        raise ValueError("creator returned an invalid VK join link")
    return match.group(0)


@dataclass
class HeadlessCreatorInfrastructure(HeadlessCreatorPoolInfrastructureMixin):
    """Protected files, binary lifecycle and VK room creation."""

    host: HostBackend
    cookies_file: Path = VK_COOKIES_FILE
    runtime_dir: Path = CREATOR_RUNTIME_DIR
    pool_dir: Path = QWDTT_POOL_DIR
    pool_state_file: Path = QWDTT_POOL_STATE
    creator_binary: Path = CREATOR_BINARY
    creator_unit: Path = CREATOR_UNIT
    creator_count: int = CREATOR_COUNT
    creator_repo: str = CREATOR_REPO
    _pool_stage: CreatorPoolStage | None = field(default=None, init=False, repr=False)

    def creator_installed(self) -> bool:
        return bool(self.host.which(str(self.creator_binary)))

    def load_vk_cookies(self) -> list[dict[str, str]]:
        try:
            raw = json.loads(self.cookies_file.read_text(encoding="utf-8"))
            return normalize_vk_cookies(raw)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return []

    def validate_credentials(self) -> list[dict[str, str]]:
        if not self.cookies_file.is_file():
            raise ValueError(f"VK cookies file is missing: {self.cookies_file}")
        raw = json.loads(self.cookies_file.read_text(encoding="utf-8"))
        cookies = normalize_vk_cookies(raw)
        self.host.ensure_directory(self.cookies_file.parent, mode=0o700)
        self.host.atomic_write(
            self.cookies_file,
            json.dumps(cookies, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        return cookies

    def forget_credentials(self) -> None:
        self.host.remove_file(self.cookies_file, missing_ok=True)

    def start_vk_room(self) -> CreatorBootstrap:
        self.validate_credentials()
        binary = self.host.which(str(self.creator_binary))
        if not binary:
            raise RuntimeError("headless VK creator is not installed")
        directory = Path(tempfile.mkdtemp(prefix="hydra-headless-creator-vk-"))
        self.host.ensure_directory(directory, mode=0o700)
        link_file = directory / "native.call.txt"
        process = self.host.popen(
            [
                binary,
                "--cookies",
                str(self.cookies_file),
                "--resources",
                "default",
                "--write-file",
                str(link_file),
            ],
            timeout=75,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            link = self._wait_for_join_file(process, link_file, timeout=60)
        except Exception:
            self._close_process(process)
            self._remove_bootstrap_dir(directory)
            raise
        return CreatorBootstrap(process, directory, link)

    def close_vk_room(self, bootstrap: CreatorBootstrap) -> None:
        self._close_process(bootstrap.process)
        self._remove_bootstrap_dir(bootstrap.directory)

    @staticmethod
    def _wait_for_join_file(process: Any, path: Path, *, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
                if lines:
                    return validate_vk_join_link(lines[-1])
            except OSError:
                pass
            if process.poll() is not None:
                break
            time.sleep(0.25)
        raise TimeoutError("headless creator did not create a VK room within 60 seconds")

    @staticmethod
    def _close_process(process: Any) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    @staticmethod
    def _remove_bootstrap_dir(path: Path) -> None:
        resolved = path.resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        try:
            resolved.relative_to(temp_root)
        except ValueError as exc:
            raise RuntimeError("refusing to remove creator directory outside temp") from exc
        if resolved.name.startswith("hydra-headless-creator-vk-"):
            shutil.rmtree(resolved, ignore_errors=True)


__all__ = [
    "CREATOR_CONFIG_DIR",
    "CREATOR_RUNTIME_DIR",
    "CreatorBootstrap",
    "HeadlessCreatorInfrastructure",
    "VK_COOKIES_FILE",
    "normalize_vk_cookies",
    "validate_vk_join_link",
]
