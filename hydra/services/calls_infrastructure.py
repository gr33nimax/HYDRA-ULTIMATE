"""Local-host runtime adapter for native Sing-Box Calls."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from hydra.contracts.hydracore_calls import supports_vps_calls
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
    """Calls-specific runtime backed by an isolated managed creator pool."""

    host: HostBackend
    credentials_source: object | None = None
    pool_source: object | None = None
    native_join_file: Path = NATIVE_JOIN_FILE

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
        source = self.pool_source
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

    def vk_parasite_supported(self) -> bool:
        return supports_vps_calls(self._capabilities())

    def singbox_running(self) -> bool:
        try:
            return self.host.run(
                ["systemctl", "is-active", "--quiet", "sing-box"],
                timeout=5,
            ).returncode == 0
        except Exception:
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
