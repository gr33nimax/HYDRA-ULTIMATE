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
from urllib.parse import urlsplit

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
    extract_call_hash,
)
from hydra.services.creator_sessions import (
    CreatorEndpoint,
    CreatorProviderAvailability,
    CreatorSessionGroup,
    CreatorSessionRequest,
)


CREATOR_CONFIG_DIR = Path("/etc/hydra/cookiesvk")
VK_COOKIES_FILE = CREATOR_CONFIG_DIR / "cookies-vk.json"
CREATOR_RUNTIME_DIR = Path("/var/lib/hydra/headless-creator")
_JOIN_CANDIDATE_RE = re.compile(r"https://[^\s\"'<>]+", re.IGNORECASE)
_JOIN_TOKEN_RE = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%-]+")
_VK_JOIN_HOSTS = frozenset({"vk.com", "vk.ru"})


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
    try:
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("creator returned an invalid VK join link") from exc
    prefix = "/call/join/"
    token = parsed.path[len(prefix):] if parsed.path.startswith(prefix) else ""
    valid = (
        parsed.scheme.lower() == "https"
        and parsed.hostname in _VK_JOIN_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port is None
        and not parsed.query
        and not parsed.fragment
        and bool(token)
        and "/" not in token
        and _JOIN_TOKEN_RE.fullmatch(token) is not None
        and re.search(r"%(?![0-9A-Fa-f]{2})", token) is None
    )
    if not valid:
        raise ValueError("creator returned an invalid VK join link")
    return link


def extract_vk_join_link(value: str) -> str:
    """Extract one strict VK join URL from creator file output."""
    raw = str(value or "").strip()
    try:
        return validate_vk_join_link(raw)
    except ValueError:
        pass
    for match in reversed(list(_JOIN_CANDIDATE_RE.finditer(raw))):
        try:
            return validate_vk_join_link(match.group(0))
        except ValueError:
            continue
    raise ValueError("creator returned an invalid VK join link")


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
    managed_consumer: str = "qwdtt"
    managed_unit_prefix: str = "hydra-headless-creator-vk"
    _pool_stage: CreatorPoolStage | None = field(default=None, init=False, repr=False)

    def creator_installed(self) -> bool:
        return bool(self.host.which(str(self.creator_binary)))

    def creator_credentials_path(self) -> str:
        return str(self.cookies_file)

    def creator_credentials_ready(self) -> bool:
        return bool(self.load_vk_cookies())

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

    def create_sessions(
        self,
        request: CreatorSessionRequest,
    ) -> CreatorSessionGroup:
        """Implement the VK driver of the provider-neutral session contract."""
        if request.provider != "vk":
            raise ValueError(f"VK creator cannot serve provider {request.provider}")
        if request.lifetime == "managed":
            if request.consumer != self.managed_consumer:
                raise ValueError("managed VK creator sessions require a known consumer")
            hashes = self.refresh_creator_pool(
                previous=list(request.previous_tokens),
                count=request.count,
            )
            links = self.read_creator_links()
            if len(links) != len(hashes):
                self.rollback_creator_pool()
                raise RuntimeError("managed VK creator returned an incomplete link pool")
            endpoints = tuple(
                CreatorEndpoint(link, token)
                for link, token in zip(links, hashes, strict=True)
            )
            return CreatorSessionGroup(request, endpoints)
        bootstrap = self.start_vk_room()
        endpoint = CreatorEndpoint(
            uri=bootstrap.join_link,
            token=extract_call_hash(bootstrap.join_link),
        )
        return CreatorSessionGroup(request, (endpoint,), handle=bootstrap)

    def creator_availability(self) -> CreatorProviderAvailability:
        return CreatorProviderAvailability(
            installed=self.creator_installed(),
            credentials_ready=bool(self.load_vk_cookies()),
        )

    def commit_sessions(self, group: CreatorSessionGroup) -> None:
        if group.request.lifetime == "managed":
            self.commit_pool(
                [endpoint.token for endpoint in group.endpoints],
                count=group.request.count,
            )

    def finalize_sessions(self, group: CreatorSessionGroup) -> None:
        if group.request.lifetime == "managed":
            self.finalize_creator_pool()

    def rollback_sessions(self, group: CreatorSessionGroup) -> None:
        if group.request.lifetime == "managed":
            self.rollback_creator_pool()
        elif isinstance(group.handle, CreatorBootstrap):
            self.close_vk_room(group.handle)

    def close_sessions(self, group: CreatorSessionGroup) -> None:
        if group.request.lifetime == "managed":
            ok, message = self.stop_creator_pool()
            if not ok:
                raise RuntimeError(message)
        elif isinstance(group.handle, CreatorBootstrap):
            self.close_vk_room(group.handle)

    def stop_managed_sessions(self, consumer: str) -> tuple[bool, str]:
        if consumer != self.managed_consumer:
            return False, f"VK creator does not know managed consumer {consumer}"
        return self.stop_creator_pool()

    def read_creator_links(self) -> list[str]:
        """Read strict full join links from the staged or committed generation."""
        metadata = self.pool_metadata()
        generation = (
            self._pool_stage.generation
            if self._pool_stage is not None
            else str(metadata.get("generation", ""))
        )
        count = (
            self._pool_stage.room_count
            if self._pool_stage is not None
            else self._room_count_from_metadata(metadata)
        )
        links: list[str] = []
        for path in self.call_files(generation=generation, count=count):
            try:
                lines = [
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                links.append(extract_vk_join_link(lines[-1]))
            except (OSError, ValueError, IndexError):
                return []
        return links if len(links) == count and len(set(links)) == count else []

    @staticmethod
    def _wait_for_join_file(process: Any, path: Path, *, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        invalid_content_seen = False
        while time.monotonic() < deadline:
            try:
                lines = [
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                for line in reversed(lines):
                    try:
                        return extract_vk_join_link(line)
                    except ValueError:
                        invalid_content_seen = True
            except OSError:
                pass
            if process.poll() is not None:
                break
            time.sleep(0.25)
        if invalid_content_seen:
            raise ValueError("creator returned an invalid VK join link")
        if process.poll() is not None:
            raise RuntimeError("headless creator exited before creating a VK room")
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
    "extract_vk_join_link",
    "normalize_vk_cookies",
    "validate_vk_join_link",
]
