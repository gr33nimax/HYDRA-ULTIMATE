"""Application owner for headless room creators and their consumers."""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from hydra.contracts import BackupResource
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_creator_models import get_creator_provider
from hydra.core.state_models import AppState
from hydra.services.configuration import restore_state_in_place
from hydra.services.plugin_actions import PluginActions


QWDTT_REFRESH_INTERVAL = 86_400
MIN_QWDTT_REFRESH_INTERVAL = 3_600
MAX_QWDTT_REFRESH_INTERVAL = 86_400
QWDTT_AUTO_FLAG = "sync_headless_creator_vk_qwdtt_enabled"
HEADLESS_CREATOR_BACKUP_RESOURCES = (
    BackupResource("/etc/hydra/cookiesvk", "tree", owner="headless_creator"),
    BackupResource("/var/lib/hydra/headless-creator", "tree", owner="headless_creator"),
    BackupResource(
        "/etc/systemd/system/hydra-headless-creator-vk@.service",
        "file",
        owner="headless_creator",
    ),
)


@dataclass(frozen=True)
class HeadlessCreatorStatus:
    installed: bool
    cookies_path: str
    cookies_ready: bool
    providers: tuple[str, ...]
    vk_qwdtt_pool_enabled: bool
    vk_qwdtt_call_count: int
    vk_qwdtt_refreshed_at: str
    vk_qwdtt_refresh_interval_seconds: int
    legacy_reinstall_required: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class HeadlessCreatorOperations(Protocol):
    def status(self, state: AppState) -> HeadlessCreatorStatus: ...
    def install(self, state: AppState) -> ServiceResult: ...
    def uninstall(self, state: AppState) -> ServiceResult: ...
    def validate_vk_credentials(self, state: AppState) -> ServiceResult: ...
    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def refresh_qwdtt_pool(self, state: AppState, *, forced: bool = False) -> ServiceResult: ...
    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def uninstall_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult: ...
    def forget_vk_credentials(self, state: AppState) -> ServiceResult: ...
    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool: ...
    def start_vk_room(self): ...
    def close_vk_room(self, bootstrap: object) -> None: ...


class UnavailableHeadlessCreatorOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Headless Creator operation is not configured: {name}")


@dataclass
class HeadlessCreatorService:
    """Coordinate one creator installation across Calls and qWDTT."""

    runtime: object
    plugin_actions: PluginActions
    save_state: Callable[[AppState], None]

    def status(self, state: AppState) -> HeadlessCreatorStatus:
        config = self._vk_config(state)
        metadata = self.runtime.pool_metadata()
        return HeadlessCreatorStatus(
            installed=self.runtime.creator_installed(),
            cookies_path=str(self.runtime.cookies_file),
            cookies_ready=bool(self.runtime.load_vk_cookies()),
            providers=("vk",),
            vk_qwdtt_pool_enabled=bool(config.get("qwdtt_pool_enabled", False)),
            vk_qwdtt_call_count=self.runtime.count_valid_creator_rooms(),
            vk_qwdtt_refreshed_at=str(metadata.get("refreshed_at", "")),
            vk_qwdtt_refresh_interval_seconds=self._refresh_interval(state),
            legacy_reinstall_required=bool(
                config.get("legacy_creator_reinstall_required", False),
            ),
        )

    def install(self, state: AppState) -> ServiceResult:
        try:
            ok, message = self.runtime.install_creator()
            if not ok:
                raise RuntimeError(message)
            return ServiceResult(True, value={"message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def uninstall(self, state: AppState) -> ServiceResult:
        calls = state.protocols.get("calls")
        if calls and calls.enabled:
            return failed_result(ValueError("disable native Calls before removing creator"))
        if self._vk_config(state).get("qwdtt_pool_enabled", False):
            return failed_result(ValueError("remove the qWDTT pool before removing creator"))
        try:
            ok, message = self.runtime.uninstall_creator()
            if not ok:
                raise RuntimeError(message)
            return ServiceResult(True, value={"message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def validate_vk_credentials(self, state: AppState) -> ServiceResult:
        try:
            self.runtime.validate_credentials()
            return ServiceResult(True, value={"valid": True})
        except Exception as exc:
            return failed_result(exc)

    def start_vk_room(self):
        return self.runtime.start_vk_room()

    def close_vk_room(self, bootstrap: object) -> None:
        self.runtime.close_vk_room(bootstrap)

    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult:
        snapshot = copy.deepcopy(state)
        previous_artifact: str | None = None
        legacy_snapshot = None
        legacy_mutated = False
        pool_staged = False
        try:
            wdtt = state.protocols.get("wdtt")
            if wdtt is None or not wdtt.enabled:
                raise ValueError("qWDTT must be enabled before creating its VK call pool")
            self.runtime.validate_credentials()
            config = self._ensure_vk_config(state)
            legacy = bool(config.get("legacy_creator_reinstall_required", False))
            if legacy:
                legacy_snapshot = self.runtime.snapshot_legacy_creator()
            installed, message = self.runtime.install_creator()
            if not installed:
                raise RuntimeError(message)
            previous = self.runtime.read_creator_hashes()
            hashes = self.runtime.refresh_creator_pool(previous=previous)
            pool_staged = True
            previous_artifact = self._publish_qwdtt_artifact(state, hashes)
            self.runtime.commit_pool(hashes)
            config["qwdtt_pool_enabled"] = True
            if legacy:
                legacy_mutated = True
                cleaned, cleanup_message = self.runtime.cleanup_legacy_creator()
                if not cleaned:
                    raise RuntimeError(cleanup_message)
                config.pop("legacy_creator_reinstall_required", None)
            self.save_state(state)
            self.runtime.finalize_creator_pool()
            return ServiceResult(True, value={"message": message, "call_count": len(hashes)})
        except Exception as exc:
            if previous_artifact is not None:
                self._restore_qwdtt_artifact(previous_artifact)
            if legacy_mutated and legacy_snapshot is not None:
                try:
                    self.runtime.restore_legacy_creator(legacy_snapshot)
                except Exception:
                    pass
            if pool_staged:
                try:
                    self.runtime.rollback_creator_pool()
                except Exception:
                    pass
            restore_state_in_place(state, snapshot)
            try:
                self.save_state(state)
            except Exception:
                pass
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def refresh_qwdtt_pool(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> ServiceResult:
        previous_artifact: str | None = None
        pool_staged = False
        try:
            if not self._vk_config(state).get("qwdtt_pool_enabled", False):
                raise ValueError("qWDTT VK call pool is disabled")
            if not forced and not self.qwdtt_pool_due(state):
                return ServiceResult(True, value={"changed": False, "message": "pool is fresh"})
            previous = self.runtime.read_creator_hashes()
            hashes = self.runtime.refresh_creator_pool(previous=previous)
            pool_staged = True
            previous_artifact = self._publish_qwdtt_artifact(state, hashes)
            self.runtime.commit_pool(hashes)
            self.runtime.finalize_creator_pool()
            return ServiceResult(True, value={"changed": True, "call_count": len(hashes)})
        except Exception as exc:
            if previous_artifact is not None:
                self._restore_qwdtt_artifact(previous_artifact)
            if pool_staged:
                try:
                    self.runtime.rollback_creator_pool()
                except Exception:
                    pass
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def _publish_qwdtt_artifact(self, state: AppState, hashes: list[str]) -> str:
        published = self.plugin_actions.execute(
            "wdtt",
            "update_call_pool_artifact",
            state=state,
            hashes=hashes,
        )
        if published is False:
            raise RuntimeError("WDTT rejected the refreshed VK call pool")
        if not isinstance(published, dict) or published.get("ok") is not True:
            raise RuntimeError("WDTT returned an invalid call-pool result")
        return str(published.get("previous_link", ""))

    def _restore_qwdtt_artifact(self, link: str) -> None:
        try:
            self.plugin_actions.execute(
                "wdtt",
                "update_call_pool_artifact",
                restore_link=link,
            )
        except Exception:
            pass

    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult:
        try:
            ok, message = self.runtime.stop_creator_pool()
            if not ok:
                raise RuntimeError(message)
            self.plugin_actions.execute("wdtt", "clear_call_pool_artifact")
            self._ensure_vk_config(state)["qwdtt_pool_enabled"] = False
            self.save_state(state)
            return ServiceResult(True, value={"message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def uninstall_qwdtt_pool(self, state: AppState) -> ServiceResult:
        result = self.stop_qwdtt_pool(state)
        if not result:
            return result
        try:
            ok, message = self.runtime.uninstall_creator_pool()
            if not ok:
                raise RuntimeError(message)
            return ServiceResult(True, value={"message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult:
        try:
            if isinstance(seconds, bool):
                raise ValueError("refresh interval must be between 1 and 24 hours")
            normalized = int(seconds)
            if not MIN_QWDTT_REFRESH_INTERVAL <= normalized <= MAX_QWDTT_REFRESH_INTERVAL:
                raise ValueError("refresh interval must be between 1 and 24 hours")
            self._ensure_vk_config(state)["qwdtt_refresh_interval_seconds"] = normalized
            self.save_state(state)
            return ServiceResult(True, value={"seconds": normalized})
        except Exception as exc:
            return failed_result(exc)

    def forget_vk_credentials(self, state: AppState) -> ServiceResult:
        calls = state.protocols.get("calls")
        if calls and calls.enabled:
            return failed_result(ValueError("disable native VK Calls first"))
        if self._vk_config(state).get("qwdtt_pool_enabled", False):
            return failed_result(ValueError("uninstall the qWDTT call pool first"))
        try:
            self.runtime.forget_credentials()
            return ServiceResult(True, value={"removed": True})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool:
        if forced:
            return True
        if not self._vk_config(state).get("qwdtt_pool_enabled", False):
            return False
        metadata = self.runtime.pool_metadata()
        stored_hashes = metadata.get("hashes", [])
        live_hashes = self.runtime.read_creator_hashes()
        if live_hashes and live_hashes != stored_hashes:
            return True
        refreshed_at = metadata.get("refreshed_at")
        if not refreshed_at:
            return True
        try:
            refreshed = datetime.fromisoformat(str(refreshed_at))
            if refreshed.tzinfo is None:
                refreshed = refreshed.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - refreshed).total_seconds()
            return elapsed >= self._refresh_interval(state)
        except (TypeError, ValueError):
            return True

    @staticmethod
    def _vk_config(state: AppState) -> dict:
        return state.headless_creator.providers.get("vk", {})

    @staticmethod
    def _ensure_vk_config(state: AppState) -> dict:
        return get_creator_provider(state.headless_creator, "vk")

    @classmethod
    def _refresh_interval(cls, state: AppState) -> int:
        value = cls._vk_config(state).get(
            "qwdtt_refresh_interval_seconds",
            QWDTT_REFRESH_INTERVAL,
        )
        try:
            normalized = int(value)
        except (TypeError, ValueError):
            return QWDTT_REFRESH_INTERVAL
        if not MIN_QWDTT_REFRESH_INTERVAL <= normalized <= MAX_QWDTT_REFRESH_INTERVAL:
            return QWDTT_REFRESH_INTERVAL
        return normalized


__all__ = [
    "HeadlessCreatorOperations",
    "HEADLESS_CREATOR_BACKUP_RESOURCES",
    "HeadlessCreatorService",
    "HeadlessCreatorStatus",
    "MAX_QWDTT_REFRESH_INTERVAL",
    "MIN_QWDTT_REFRESH_INTERVAL",
    "QWDTT_AUTO_FLAG",
    "QWDTT_REFRESH_INTERVAL",
    "UnavailableHeadlessCreatorOperations",
]
