"""Application use-cases for native VK Calls and the qWDTT call pool."""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol

from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_models import AppState, get_protocol
from hydra.services.configuration import restore_state_in_place
from hydra.services.plugin_actions import PluginActions
from hydra.services.protocols import ProtocolService


QWDTT_REFRESH_INTERVAL = 86_400
MIN_QWDTT_REFRESH_INTERVAL = 3_600
MAX_QWDTT_REFRESH_INTERVAL = 86_400
QWDTT_AUTO_FLAG = "sync_calls_qwdtt_pool_enabled"


@dataclass(frozen=True)
class CallsStatus:
    feature_supported: bool
    cookies_ready: bool
    native_enabled: bool
    native_link_ready: bool
    native_running: bool
    qwdtt_pool_enabled: bool
    qwdtt_call_count: int
    qwdtt_refreshed_at: str
    qwdtt_refresh_interval_seconds: int
    legacy_creator_reinstall_required: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CallClientProfile:
    name: str
    platform: str
    join_link: str
    config: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


class CallOperations(Protocol):
    def status(self, state: AppState) -> CallsStatus: ...
    def enable_native_vk(self, state: AppState) -> ServiceResult: ...
    def rotate_native_vk(self, state: AppState) -> ServiceResult: ...
    def disable_native_vk(self, state: AppState, *, purge_link: bool = False) -> ServiceResult: ...
    def native_client_profile(self, state: AppState) -> CallClientProfile: ...
    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def refresh_qwdtt_pool(self, state: AppState, *, forced: bool = False) -> ServiceResult: ...
    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def uninstall_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult: ...
    def forget_vk_credentials(self, state: AppState) -> ServiceResult: ...
    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool: ...


class UnavailableCallOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Calls operation is not configured: {name}")


@dataclass
class CallsService:
    """Coordinate protected files, plugin lifecycle and WDTT projection."""

    runtime: object
    protocols: ProtocolService
    plugin_actions: PluginActions
    save_state: Callable[[AppState], None]
    apply_config: Callable[[AppState], bool]
    last_apply_error: Callable[[], str] = lambda: ""
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def status(self, state: AppState) -> CallsStatus:
        desired = state.protocols.get("calls")
        config = desired.config if desired is not None else {}
        metadata = self.runtime.pool_metadata()
        hashes = self.runtime.read_creator_hashes()
        native_link_ready = bool(self.runtime.load_native_join_link())
        native_enabled = bool(desired and desired.enabled)
        return CallsStatus(
            feature_supported=self.runtime.feature_supported(),
            cookies_ready=bool(self.runtime.load_vk_cookies()),
            native_enabled=native_enabled,
            native_link_ready=native_link_ready,
            native_running=bool(
                native_enabled
                and native_link_ready
                and self.runtime.singbox_running()
            ),
            qwdtt_pool_enabled=bool(config.get("qwdtt_pool_enabled", False)),
            qwdtt_call_count=len(hashes),
            qwdtt_refreshed_at=str(metadata.get("refreshed_at", "")),
            qwdtt_refresh_interval_seconds=self._refresh_interval(state),
            legacy_creator_reinstall_required=bool(
                config.get("legacy_creator_reinstall_required", False),
            ),
        )

    def enable_native_vk(self, state: AppState) -> ServiceResult:
        return self._native_transition(state, rotate=False)

    def rotate_native_vk(self, state: AppState) -> ServiceResult:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            return failed_result(ValueError("native VK Calls are not enabled"))
        return self._native_transition(state, rotate=True)

    def _native_transition(self, state: AppState, *, rotate: bool) -> ServiceResult:
        if not self._lock.acquire(blocking=False):
            return failed_result(
                RuntimeError("another Calls operation is already running"),
                fallback=ErrorCode.CONFLICT,
            )
        snapshot = copy.deepcopy(state)
        previous_link = self.runtime.load_native_join_link()
        bootstrap = None
        try:
            if not self.runtime.feature_supported():
                raise RuntimeError(
                    "installed Sing-Box does not support Call; update Sing-Box Extended to 2.6.0 or newer",
                )
            cookies = self.runtime.validate_credentials()
            bootstrap = self.runtime.start_native_bootstrap(cookies)
            self.runtime.write_native_join_link(bootstrap.join_link)
            desired = get_protocol(state, "calls")
            if not desired.installed:
                applied = self.protocols.activate(state, "calls")
            elif not desired.enabled:
                applied = self.protocols.enable(state, "calls")
            else:
                applied = self.apply_config(state)
            if not applied:
                raise RuntimeError(
                    self.last_apply_error() or "failed to apply native VK Calls configuration",
                )
            if not self.runtime.wait_main_join(bootstrap.join_link):
                raise TimeoutError("main Sing-Box did not join the new VK call")
            return ServiceResult(
                True,
                value={
                    "operation": "rotate" if rotate else "enable",
                    "profile": "admin",
                },
            )
        except Exception as exc:
            self._restore_native_transition(state, snapshot, previous_link)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            if bootstrap is not None:
                self.runtime.close_native_bootstrap(bootstrap)
            self._lock.release()

    def _restore_native_transition(
        self,
        state: AppState,
        snapshot: AppState,
        previous_link: str,
    ) -> None:
        try:
            if previous_link:
                self.runtime.write_native_join_link(previous_link)
            else:
                self.runtime.remove_native_join_link()
            restore_state_in_place(state, snapshot)
            self.save_state(state)
            self.apply_config(state)
        except Exception:
            pass

    def disable_native_vk(
        self,
        state: AppState,
        *,
        purge_link: bool = False,
    ) -> ServiceResult:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            if purge_link:
                self.runtime.remove_native_join_link()
            return ServiceResult(True, value={"changed": False})
        try:
            if not self.protocols.disable(state, "calls"):
                raise RuntimeError(
                    self.last_apply_error() or "failed to disable native VK Calls",
                )
            if purge_link:
                self.runtime.remove_native_join_link()
            return ServiceResult(True, value={"changed": True})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def native_client_profile(self, state: AppState) -> CallClientProfile:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            raise ValueError("native VK Calls are not enabled")
        link = self.runtime.load_native_join_link()
        if not link:
            raise RuntimeError("native VK call join link is unavailable")
        config = {
            "log": {"level": "info", "timestamp": True},
            "dns": {"servers": [{"type": "local", "tag": "default"}]},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
            }],
            "outbounds": [{
                "type": "call",
                "tag": "call-vk-out",
                "platform": "vk",
                "read_buffer": int(desired.config.get("read_buffer", 32768)),
                "join_link": link,
            }],
            "route": {
                "final": "call-vk-out",
                "default_domain_resolver": "default",
                "auto_detect_interface": True,
            },
        }
        return CallClientProfile(
            name="HYDRA Calls · VK · admin",
            platform="vk",
            join_link=link,
            config=json.dumps(config, ensure_ascii=False, indent=2),
        )

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
            calls = get_protocol(state, "calls")
            legacy = bool(calls.config.get("legacy_creator_reinstall_required", False))
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
            calls.config["qwdtt_pool_enabled"] = True
            if legacy:
                legacy_mutated = True
                cleaned, cleanup_message = self.runtime.cleanup_legacy_creator()
                if not cleaned:
                    raise RuntimeError(cleanup_message)
                calls.config.pop("legacy_creator_reinstall_required", None)
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
            calls = state.protocols.get("calls")
            if calls is None or not calls.config.get("qwdtt_pool_enabled", False):
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
            calls = get_protocol(state, "calls")
            calls.config["qwdtt_pool_enabled"] = False
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
            calls = get_protocol(state, "calls")
            calls.config["qwdtt_refresh_interval_seconds"] = normalized
            self.save_state(state)
            return ServiceResult(True, value={"seconds": normalized})
        except Exception as exc:
            return failed_result(exc)

    def forget_vk_credentials(self, state: AppState) -> ServiceResult:
        desired = state.protocols.get("calls")
        config = desired.config if desired is not None else {}
        if desired and desired.enabled:
            return failed_result(ValueError("disable native VK Calls first"))
        if config.get("qwdtt_pool_enabled", False):
            return failed_result(ValueError("uninstall the qWDTT call pool first"))
        try:
            self.runtime.forget_credentials()
            return ServiceResult(True, value={"removed": True})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool:
        if forced:
            return True
        desired = state.protocols.get("calls")
        if desired is None or not desired.config.get("qwdtt_pool_enabled", False):
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
    def _refresh_interval(state: AppState) -> int:
        desired = state.protocols.get("calls")
        value = (
            desired.config.get("qwdtt_refresh_interval_seconds", QWDTT_REFRESH_INTERVAL)
            if desired is not None
            else QWDTT_REFRESH_INTERVAL
        )
        try:
            normalized = int(value)
        except (TypeError, ValueError):
            return QWDTT_REFRESH_INTERVAL
        if not MIN_QWDTT_REFRESH_INTERVAL <= normalized <= MAX_QWDTT_REFRESH_INTERVAL:
            return QWDTT_REFRESH_INTERVAL
        return normalized


__all__ = [
    "CallClientProfile",
    "CallOperations",
    "CallsService",
    "CallsStatus",
    "MAX_QWDTT_REFRESH_INTERVAL",
    "MIN_QWDTT_REFRESH_INTERVAL",
    "QWDTT_AUTO_FLAG",
    "QWDTT_REFRESH_INTERVAL",
    "UnavailableCallOperations",
]
