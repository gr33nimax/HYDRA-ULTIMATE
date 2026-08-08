"""Local-host runtime adapter for native VK Calls."""
from __future__ import annotations

import json
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hydra.core.host import HostBackend
from hydra.services.calls_creator_infrastructure import (
    CREATOR_BINARY,
    CREATOR_COUNT,
    CREATOR_REPO,
    CREATOR_UNIT,
    QWDTT_POOL_DIR,
    QWDTT_POOL_STATE,
    CallsCreatorInfrastructureMixin,
    CreatorPoolStage,
    LegacyCreatorSnapshot,
    extract_call_hash,
)


CALLS_CONFIG_DIR = Path("/etc/hydra/calls/vk")
CALLS_RUNTIME_DIR = Path("/var/lib/hydra/calls/vk")
CALLS_COOKIES_FILE = CALLS_CONFIG_DIR / "cookies-vk.json"
NATIVE_JOIN_FILE = CALLS_RUNTIME_DIR / "native.join"
_JOIN_RE = re.compile(r"https://vk\.com/call/join/[A-Za-z0-9._~-]+")


@dataclass(frozen=True)
class NativeBootstrap:
    process: Any
    directory: Path
    join_link: str


def _normalized_cookies(value: object) -> list[dict[str, str]]:
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


def validate_join_link(value: str) -> str:
    link = str(value or "").strip()
    match = _JOIN_RE.fullmatch(link)
    if match is None:
        raise ValueError("Sing-Box returned an invalid VK join link")
    return match.group(0)


@dataclass
class CallsInfrastructure(CallsCreatorInfrastructureMixin):
    """Host-backed implementation shared by CallsService and CallsPlugin."""

    host: HostBackend
    cookies_file: Path = CALLS_COOKIES_FILE
    native_join_file: Path = NATIVE_JOIN_FILE
    pool_dir: Path = QWDTT_POOL_DIR
    pool_state_file: Path = QWDTT_POOL_STATE
    creator_binary: Path = CREATOR_BINARY
    creator_unit: Path = CREATOR_UNIT
    creator_count: int = CREATOR_COUNT
    creator_repo: str = CREATOR_REPO
    _pool_stage: CreatorPoolStage | None = field(default=None, init=False, repr=False)

    def load_vk_cookies(self) -> list[dict[str, str]]:
        try:
            raw = json.loads(self.cookies_file.read_text(encoding="utf-8"))
            return _normalized_cookies(raw)
        except FileNotFoundError:
            return []
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return []

    def validate_credentials(self) -> list[dict[str, str]]:
        if not self.cookies_file.is_file():
            raise ValueError(f"VK cookies file is missing: {self.cookies_file}")
        raw = json.loads(self.cookies_file.read_text(encoding="utf-8"))
        cookies = _normalized_cookies(raw)
        self.host.ensure_directory(self.cookies_file.parent, mode=0o700)
        self.host.atomic_write(
            self.cookies_file,
            json.dumps(cookies, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        return cookies

    def load_native_join_link(self) -> str:
        try:
            return validate_join_link(
                self.native_join_file.read_text(encoding="utf-8"),
            )
        except (OSError, ValueError):
            return ""

    def write_native_join_link(self, link: str) -> None:
        normalized = validate_join_link(link)
        self.host.ensure_directory(self.native_join_file.parent, mode=0o700)
        self.host.atomic_write(self.native_join_file, normalized + "\n", mode=0o600)

    def remove_native_join_link(self) -> None:
        self.host.remove_file(self.native_join_file, missing_ok=True)

    def feature_supported(self) -> bool:
        binary = self.host.which("sing-box")
        if not binary:
            return False
        try:
            config = {
                "log": {"level": "warn"},
                "inbounds": [{"type": "call", "tag": "probe", "platform": "vk"}],
                "outbounds": [{"type": "direct", "tag": "direct"}],
            }
            with tempfile.TemporaryDirectory(prefix="hydra-calls-probe-") as work:
                path = Path(work) / "config.json"
                self.host.atomic_write(path, json.dumps(config), mode=0o600)
                result = self.host.run(
                    [binary, "check", "-c", str(path)],
                    timeout=15,
                    capture_output=True,
                    text=True,
                )
            return result.returncode == 0
        except Exception:
            return False

    def singbox_running(self) -> bool:
        try:
            return self.host.run(
                ["systemctl", "is-active", "--quiet", "sing-box"],
                timeout=5,
            ).returncode == 0
        except Exception:
            return False

    def start_native_bootstrap(self, cookies: list[dict[str, str]]) -> NativeBootstrap:
        binary = self.host.which("sing-box")
        if not binary:
            raise RuntimeError("sing-box is not installed")
        directory = Path(tempfile.mkdtemp(prefix="hydra-calls-bootstrap-"))
        config_path = directory / "config.json"
        config = {
            "log": {"level": "info", "timestamp": True},
            "dns": {"servers": [{"type": "local", "tag": "default"}]},
            "inbounds": [{
                "type": "call",
                "tag": "calls-vk-bootstrap",
                "platform": "vk",
                "read_buffer": 32768,
                "cookies": cookies,
                "join_link": "",
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "final": "direct",
                "default_domain_resolver": "default",
                "auto_detect_interface": True,
            },
        }
        self.host.atomic_write(config_path, json.dumps(config), mode=0o600)
        process = self.host.popen(
            [binary, "run", "-c", str(config_path)],
            timeout=75,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            link = self._read_process_join_link(process, timeout=60)
        except Exception:
            self._close_process(process)
            self._remove_bootstrap_dir(directory)
            raise
        return NativeBootstrap(process, directory, link)

    def close_native_bootstrap(self, bootstrap: NativeBootstrap) -> None:
        self._close_process(bootstrap.process)
        self._remove_bootstrap_dir(bootstrap.directory)

    @staticmethod
    def _read_process_join_link(process: Any, *, timeout: float) -> str:
        output: queue.Queue[str | None] = queue.Queue()

        def reader() -> None:
            stream = getattr(process, "stdout", None)
            if stream is None:
                output.put(None)
                return
            for line in iter(stream.readline, ""):
                output.put(str(line))
            output.put(None)

        threading.Thread(target=reader, daemon=True).start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None and output.empty():
                break
            try:
                wait = min(0.25, max(0.01, deadline - time.monotonic()))
                line = output.get(timeout=wait)
            except queue.Empty:
                continue
            if line is None:
                break
            match = _JOIN_RE.search(line)
            if match is not None:
                return validate_join_link(match.group(0))
        raise TimeoutError("Sing-Box did not create a VK call within 60 seconds")

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
            raise RuntimeError("refusing to remove bootstrap directory outside temp") from exc
        if resolved.name.startswith("hydra-calls-bootstrap-"):
            shutil.rmtree(resolved, ignore_errors=True)

    def wait_main_join(self, link: str, *, timeout: int = 30) -> bool:
        normalized = validate_join_link(link)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.host.run(
                ["journalctl", "-u", "sing-box", "--since", "2 minutes ago", "--no-pager"],
                timeout=5,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and normalized in str(result.stdout or ""):
                return True
            time.sleep(1)
        return False

    def forget_credentials(self) -> None:
        self.host.remove_file(self.cookies_file, missing_ok=True)


__all__ = [
    "CALLS_COOKIES_FILE",
    "CALLS_RUNTIME_DIR",
    "CREATOR_BINARY",
    "CREATOR_UNIT",
    "CallsInfrastructure",
    "CreatorPoolStage",
    "LegacyCreatorSnapshot",
    "NativeBootstrap",
    "extract_call_hash",
    "validate_join_link",
]
