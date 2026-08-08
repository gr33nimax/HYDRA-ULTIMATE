"""Application use-cases for native Sing-Box Calls."""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol

from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_models import AppState, get_protocol
from hydra.services.configuration import restore_state_in_place
from hydra.services.creator_sessions import (
    CreatorSessionGroup,
    CreatorSessionRequest,
    CreatorSessions,
)
from hydra.services.protocols import ProtocolService


@dataclass(frozen=True)
class CallsStatus:
    feature_supported: bool
    creator_installed: bool
    cookies_ready: bool
    native_enabled: bool
    native_link_ready: bool
    native_running: bool

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
    def reinstall_native_vk(self, state: AppState) -> ServiceResult: ...
    def rotate_native_vk(self, state: AppState) -> ServiceResult: ...
    def disable_native_vk(self, state: AppState, *, purge_link: bool = False) -> ServiceResult: ...
    def uninstall_native_vk(self, state: AppState) -> ServiceResult: ...
    def native_client_profile(self, state: AppState) -> CallClientProfile: ...


class UnavailableCallOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Calls operation is not configured: {name}")


class CallsRuntime(Protocol):
    def feature_supported(self) -> bool: ...
    def load_native_join_link(self) -> str: ...
    def write_native_join_link(self, link: str) -> None: ...
    def remove_native_join_link(self) -> None: ...
    def singbox_running(self) -> bool: ...
    def wait_main_join(self, link: str) -> bool: ...


@dataclass
class CallsService:
    """Coordinate native Call lifecycle using the shared headless creator."""

    runtime: CallsRuntime
    creator: CreatorSessions
    protocols: ProtocolService
    save_state: Callable[[AppState], None]
    apply_config: Callable[[AppState], bool]
    last_apply_error: Callable[[], str] = lambda: ""
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def status(self, state: AppState) -> CallsStatus:
        desired = state.protocols.get("calls")
        link_ready = bool(self.runtime.load_native_join_link())
        enabled = bool(desired and desired.enabled)
        creator_status = self.creator.availability("vk")
        return CallsStatus(
            feature_supported=self.runtime.feature_supported(),
            creator_installed=creator_status.installed,
            cookies_ready=creator_status.credentials_ready,
            native_enabled=enabled,
            native_link_ready=link_ready,
            native_running=bool(enabled and link_ready and self.runtime.singbox_running()),
        )

    def enable_native_vk(self, state: AppState) -> ServiceResult:
        return self._native_transition(state, rotate=False)

    def reinstall_native_vk(self, state: AppState) -> ServiceResult:
        desired = state.protocols.get("calls")
        if desired is None or not desired.installed:
            return failed_result(ValueError("native VK Calls are not installed"))
        return self._native_transition(state, rotate=True)

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
        session_group: CreatorSessionGroup | None = None
        close_error = ""
        try:
            if not self.runtime.feature_supported():
                raise RuntimeError(
                    "installed Sing-Box does not support Call; update Sing-Box Extended to 2.6.0 or newer",
                )
            session_group = self.creator.create(CreatorSessionRequest(
                provider="vk",
                consumer="calls",
                lifetime="transient",
            ))
            join_link = session_group.endpoints[0].uri
            if not join_link:
                raise RuntimeError("VK creator returned no join link")
            self.runtime.write_native_join_link(join_link)
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
            if not self.runtime.wait_main_join(join_link):
                raise TimeoutError("main Sing-Box did not join the new VK call")
            result = ServiceResult(
                True,
                value={"operation": "rotate" if rotate else "enable", "profile": "admin"},
            )
        except Exception as exc:
            self._restore_native_transition(state, snapshot, previous_link)
            result = failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            try:
                if session_group is not None:
                    self.creator.close(session_group)
            except Exception as exc:
                close_error = str(exc) or exc.__class__.__name__
            finally:
                self._lock.release()
        if result and close_error:
            value = dict(result.value or {})
            value["cleanup_warning"] = close_error
            return ServiceResult(True, value=value)
        return result

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
        except Exception:
            pass
        restore_state_in_place(state, snapshot)
        try:
            self.save_state(state)
        except Exception:
            pass
        try:
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

    def uninstall_native_vk(self, state: AppState) -> ServiceResult:
        if not self._lock.acquire(blocking=False):
            return failed_result(
                RuntimeError("another Calls operation is already running"),
                fallback=ErrorCode.CONFLICT,
            )
        snapshot = copy.deepcopy(state)
        previous_link = self.runtime.load_native_join_link()
        desired = state.protocols.get("calls")
        was_installed = bool(desired and desired.installed)
        try:
            if was_installed and not self.protocols.uninstall(state, "calls"):
                raise RuntimeError(
                    self.last_apply_error() or "failed to uninstall native VK Calls",
                )
            self.runtime.remove_native_join_link()
            return ServiceResult(
                True,
                value={"changed": bool(was_installed or previous_link)},
            )
        except Exception as exc:
            self._restore_native_transition(state, snapshot, previous_link)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._lock.release()

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


__all__ = [
    "CallClientProfile",
    "CallOperations",
    "CallsRuntime",
    "CallsService",
    "CallsStatus",
    "UnavailableCallOperations",
]
