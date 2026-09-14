"""Local-host runtime adapter for native Sing-Box Calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.contracts.calls_configuration import CALL_COUNT
from hydra.contracts.hydracore_calls import supports_vps_contract
from hydra.core.host import HostBackend
from hydra.services.calls_slot_replacement import CallsSlotReplacement, stage_calls_slot_replacement
from hydra.services.headless_creator_infrastructure import validate_vk_join_link
from hydra.services.headless_creator_release import extract_call_hash


CALLS_RUNTIME_DIR = Path("/var/lib/hydra/calls/vk")
NATIVE_JOIN_FILE = CALLS_RUNTIME_DIR / "native.join"
CALLS_POOL_DIR = CALLS_RUNTIME_DIR / "pool"
CALLS_POOL_STATE = CALLS_POOL_DIR / "state.json"
CALLS_PROBE_STATE = CALLS_POOL_DIR / "probe-state.json"
CALLS_CREATOR_UNIT = Path(
    "/etc/systemd/system/hydra-headless-creator-vk-calls@.service",
)
validate_join_link = validate_vk_join_link


@dataclass
class CallsInfrastructure:
    """Calls-specific runtime backed by an isolated managed creator pool."""

    host: HostBackend
    credentials_source: Any | None = None
    pool_source: Any | None = None
    native_join_file: Path = NATIVE_JOIN_FILE
    _slot_replacement: CallsSlotReplacement | None = None

    def remove_native_join_link(self) -> None:
        self.host.remove_file(self.native_join_file, missing_ok=True)

    def load_native_join_links(self) -> list[str]:
        source = self.pool_source
        if source is None:
            return []
        try:
            links = self._read_pool_links(source)
        except (AttributeError, OSError, TypeError, ValueError):
            return []
        if len(links) != CALL_COUNT or len(set(links)) != CALL_COUNT:
            return []
        return links if self._creator_units_active(source) else []

    def _creator_units_active(self, source: Any) -> bool:
        try:
            units = list(source.creator_units(count=CALL_COUNT))
        except (AttributeError, OSError, TypeError, ValueError):
            return False
        return len(units) == CALL_COUNT and all(
            not self.host.run(
                ["systemctl", "is-active", "--quiet", unit],
                timeout=5,
            ).returncode
            for unit in units
        )

    def load_native_join_tokens(self) -> list[str]:
        links = self.load_native_join_links()
        try:
            tokens = [extract_call_hash(link) for link in links]
        except ValueError:
            return []
        return tokens if len(tokens) == CALL_COUNT and len(set(tokens)) == len(tokens) else []

    def _read_pool_links(self, source: Any) -> list[str]:
        metadata_reader = getattr(source, "pool_metadata", None)
        metadata = metadata_reader() if callable(metadata_reader) else {}
        slots = metadata.get("slots") if isinstance(metadata, dict) else None
        if not isinstance(slots, list) or len(slots) != CALL_COUNT:
            return [validate_join_link(value) for value in source.read_creator_links()]
        links: list[str] = []
        for index, entry in enumerate(slots, start=1):
            if not isinstance(entry, dict) or entry.get("generation") not in {"a", "b"}:
                raise ValueError("invalid VK Calls slot metadata")
            path = source.pool_dir / f"{entry['generation']}-{index}.call.txt"
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            links.append(validate_join_link(lines[-1]))
        return links

    def stage_native_slot(self, slot: int) -> list[str]:
        if self.pool_source is None or self._slot_replacement is not None:
            raise RuntimeError("VK Calls room replacement is unavailable")
        replacement = stage_calls_slot_replacement(self.pool_source, slot)
        self._slot_replacement = replacement
        return replacement.links

    def finalize_native_slot(self) -> None:
        if self._slot_replacement is None:
            raise RuntimeError("VK Calls room replacement was not staged")
        self._slot_replacement.finalize()
        self._slot_replacement = None

    def rollback_native_slot(self) -> None:
        if self._slot_replacement is None:
            return
        try:
            self._slot_replacement.rollback()
        finally:
            self._slot_replacement = None

    def pool_metadata(self) -> dict[str, object]:
        source = self.pool_source
        if source is None:
            return {}
        try:
            value = source.pool_metadata()
            return value if isinstance(value, dict) else {}
        except (AttributeError, OSError, TypeError, ValueError):
            return {}

    def ensure_creator_installed(self) -> tuple[bool, str]:
        source = self.pool_source
        if source is None:
            return False, "VK creator runtime is not configured"
        try:
            return source.install_creator()
        except (AttributeError, OSError, RuntimeError, ValueError) as exc:
            message = str(exc)
            if not message:
                message = exc.__class__.__name__
            return False, message

    def import_vk_cookies(self, source_path: Path) -> None:
        source = self.credentials_source or self.pool_source
        if source is None:
            raise RuntimeError("VK creator runtime is not configured")
        importer = getattr(source, "import_vk_cookies", None)
        if not callable(importer):
            raise RuntimeError("VK creator runtime cannot import cookies")
        importer(source_path)

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

    def _contract(self) -> dict:
        binary = self.host.which("sing-box")
        if not binary:
            return {}
        try:
            result = self.host.run(
                [binary, "hydra", "contract", "--json"],
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
        return supports_vps_contract(self._contract())

    def singbox_running(self) -> bool:
        try:
            return not self.host.run(
                ["systemctl", "is-active", "--quiet", "sing-box"],
                timeout=5,
            ).returncode
        except Exception:
            return False


__all__ = [
    "CALLS_RUNTIME_DIR",
    "CALLS_CREATOR_UNIT",
    "CALLS_POOL_DIR",
    "CALLS_POOL_STATE",
    "CALLS_PROBE_STATE",
    "CallsInfrastructure",
    "NATIVE_JOIN_FILE",
    "validate_join_link",
]
