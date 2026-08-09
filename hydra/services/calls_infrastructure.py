"""Local-host runtime adapter for native Sing-Box Calls."""
from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.services.headless_creator_infrastructure import validate_vk_join_link


CALLS_RUNTIME_DIR = Path("/var/lib/hydra/calls/vk")
NATIVE_JOIN_FILE = CALLS_RUNTIME_DIR / "native.join"
CALLS_POOL_DIR = CALLS_RUNTIME_DIR / "pool"
CALLS_POOL_STATE = CALLS_POOL_DIR / "state.json"
CALLS_CREATOR_UNIT = Path(
    "/etc/systemd/system/hydra-headless-creator-vk-calls@.service",
)


validate_join_link = validate_vk_join_link


@dataclass
class CallsInfrastructure:
    """Calls-specific runtime plus an injected creator credential source."""

    host: HostBackend
    credentials_source: object | None = None
    pool_source: object | None = None
    native_join_file: Path = NATIVE_JOIN_FILE

    def load_vk_cookies(self) -> list[dict[str, str]]:
        source = self.credentials_source
        if source is None:
            return []
        return list(source.load_vk_cookies())

    def load_native_join_link(self) -> str:
        try:
            return validate_join_link(self.native_join_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""

    def write_native_join_link(self, link: str) -> None:
        normalized = validate_join_link(link)
        self.host.ensure_directory(self.native_join_file.parent, mode=0o700)
        self.host.atomic_write(self.native_join_file, normalized + "\n", mode=0o600)

    def remove_native_join_link(self) -> None:
        self.host.remove_file(self.native_join_file, missing_ok=True)

    def load_native_join_links(self) -> list[str]:
        source = self.pool_source
        if source is None:
            return []
        try:
            links = [validate_join_link(value) for value in source.read_creator_links()]
        except (AttributeError, OSError, TypeError, ValueError):
            return []
        return links if 1 <= len(links) <= 4 and len(set(links)) == len(links) else []

    def load_native_join_tokens(self) -> list[str]:
        source = self.pool_source
        if source is None:
            return []
        try:
            tokens = [str(value) for value in source.read_creator_hashes()]
        except (AttributeError, OSError, TypeError, ValueError):
            return []
        return tokens if len(tokens) <= 4 and len(set(tokens)) == len(tokens) else []

    def ensure_creator_installed(self) -> tuple[bool, str]:
        source = self.pool_source or self.credentials_source
        if source is None:
            return False, "VK creator runtime is not configured"
        try:
            return source.install_creator()
        except (AttributeError, OSError, RuntimeError, ValueError) as exc:
            return False, str(exc) or exc.__class__.__name__

    def snapshot_native_pool(self) -> object:
        source = self.pool_source
        if source is None:
            return None
        return source.snapshot_creator_pool()

    def restore_native_pool(self, snapshot: object) -> None:
        source = self.pool_source
        if source is None or snapshot is None:
            return
        source.restore_creator_pool(snapshot)

    def uninstall_native_pool(self) -> tuple[bool, str]:
        source = self.pool_source
        if source is None:
            return True, "Calls creator pool is not configured"
        return source.uninstall_creator_pool()

    def _capabilities(self) -> dict:
        binary = self.host.which("sing-box")
        if not binary:
            return {}
        try:
            result = self.host.run(
                [binary, "hydra", "capabilities", "--json"],
                timeout=10,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {}
            payload = json.loads(str(result.stdout or ""))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def multi_user_supported(self) -> bool:
        payload = self._capabilities()
        features = payload.get("features", {})
        protocols = payload.get("protocols", {})
        modes = protocols.get("call_modes", []) if isinstance(protocols, dict) else []
        return bool(
            isinstance(features, dict)
            and features.get("call_vk_multi_user") is True
            and isinstance(modes, list)
            and all(isinstance(mode, str) for mode in modes)
            and {"p2p", "multi_user"}.issubset(modes)
        )

    def feature_supported(self) -> bool:
        payload = self._capabilities()
        protocols = payload.get("protocols", {})
        modes = protocols.get("call_modes", ()) if isinstance(protocols, dict) else ()
        if isinstance(modes, list) and "p2p" in modes:
            return True
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


__all__ = [
    "CALLS_RUNTIME_DIR",
    "CALLS_CREATOR_UNIT",
    "CALLS_POOL_DIR",
    "CALLS_POOL_STATE",
    "CallsInfrastructure",
    "NATIVE_JOIN_FILE",
    "validate_join_link",
]
