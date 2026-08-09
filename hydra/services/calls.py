"""Application use-cases for native Sing-Box Calls."""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass, field
from typing import Callable

from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_kernel_models import KERNEL_HYDRACORE
from hydra.core.state_models import AppState, get_protocol
from hydra.services.configuration import restore_state_in_place
from hydra.services.calls_contracts import (
    CallClientProfile,
    CallOperationLease,
    CallOperationLock,
    CallOperations,
    CallsRuntime,
    CallsStatus,
    NoopCallOperationLock,
    UnavailableCallOperations,
)
from hydra.services.creator_sessions import (
    CreatorSessionGroup,
    CreatorSessionRequest,
    CreatorSessions,
)
from hydra.services.protocols import ProtocolService
from hydra.plugins.calls.configuration import (
    CALL_MODE_MULTI_USER,
    CALL_MODE_P2P,
    DEFAULT_CALL_PORT,
    DEFAULT_ROOM_COUNT,
    MAX_JOIN_LINKS,
    call_mode,
    multi_user_outbound,
)
from hydra.utils.crypto import gen_token


@dataclass
class CallsService:
    """Coordinate native Call lifecycle using the shared headless creator."""

    runtime: CallsRuntime
    creator: CreatorSessions
    protocols: ProtocolService
    save_state: Callable[[AppState], None]
    apply_config: Callable[[AppState], bool]
    operation_lock: CallOperationLock = field(default_factory=NoopCallOperationLock)
    last_apply_error: Callable[[], str] = lambda: ""
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _multi_user_supported(self) -> bool:
        probe = getattr(self.runtime, "multi_user_supported", None)
        return bool(probe()) if callable(probe) else False

    def _begin_operation(self) -> tuple[CallOperationLease | None, ServiceResult | None]:
        if not self._lock.acquire(blocking=False):
            return None, failed_result(
                RuntimeError("another Calls operation is already running"),
                fallback=ErrorCode.CONFLICT,
            )
        try:
            lease = self.operation_lock.try_acquire()
        except Exception as exc:
            self._lock.release()
            return None, failed_result(exc, fallback=ErrorCode.HOST_OPERATION)
        if lease is None:
            self._lock.release()
            return None, failed_result(
                RuntimeError("another Calls process owns the operation lock"),
                fallback=ErrorCode.CONFLICT,
            )
        return lease, None

    def _end_operation(self, lease: CallOperationLease) -> None:
        try:
            lease.release()
        finally:
            self._lock.release()

    def status(self, state: AppState) -> CallsStatus:
        desired = state.protocols.get("calls")
        link_ready = bool(self.runtime.load_native_join_link())
        enabled = bool(desired and desired.enabled)
        mode = call_mode(state)
        links = self.runtime.load_native_join_links() if mode == CALL_MODE_MULTI_USER else []
        if mode == CALL_MODE_MULTI_USER:
            link_ready = bool(links)
        creator_status = self.creator.availability("vk")
        return CallsStatus(
            feature_supported=(
                self._multi_user_supported()
                if mode == CALL_MODE_MULTI_USER
                else self.runtime.feature_supported()
            ),
            creator_installed=creator_status.installed,
            cookies_ready=creator_status.credentials_ready,
            native_enabled=enabled,
            native_link_ready=link_ready,
            native_running=bool(enabled and link_ready and self.runtime.singbox_running()),
            native_mode=mode,
            room_count=len(links),
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

    def set_room_count(self, state: AppState, count: int) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        try:
            if type(count) is not int or not 1 <= count <= MAX_JOIN_LINKS:
                raise ValueError("Calls room_count must be between 1 and 4")
            desired = get_protocol(state, "calls")
            before = copy.deepcopy(desired.config)
            desired.config["room_count"] = count
            try:
                self.save_state(state)
            except Exception:
                desired.config = before
                raise
            return ServiceResult(True, value={"room_count": count})
        except Exception as exc:
            return failed_result(exc)
        finally:
            self._end_operation(lease)

    def _native_transition(self, state: AppState, *, rotate: bool) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        multi_supported = self._multi_user_supported()
        preflight_error = ""
        if state.kernel.provider == KERNEL_HYDRACORE and not multi_supported:
            preflight_error = (
                "installed Hydracore does not expose the exact "
                "call_vk_multi_user capability contract"
            )
        elif not multi_supported and not self.runtime.feature_supported():
            preflight_error = (
                "installed Sing-Box does not support Call; "
                "update Sing-Box Extended to 2.6.0 or newer"
            )
        if preflight_error:
            self._end_operation(lease)
            return failed_result(RuntimeError(preflight_error), fallback=ErrorCode.OPERATION_FAILED)
        snapshot = copy.deepcopy(state)
        previous_link = self.runtime.load_native_join_link()
        session_group: CreatorSessionGroup | None = None
        close_error = ""
        managed = False
        finalized = False
        try:
            installer = getattr(self.runtime, "ensure_creator_installed", None)
            if callable(installer):
                installed, install_message = installer()
                if not installed:
                    raise RuntimeError(install_message)
            desired = get_protocol(state, "calls")
            managed = multi_supported
            if managed:
                count = desired.config.get("room_count", DEFAULT_ROOM_COUNT)
                if type(count) is not int or not 1 <= count <= MAX_JOIN_LINKS:
                    raise ValueError("Calls room_count must be between 1 and 4")
                desired.config.update({
                    "mode": CALL_MODE_MULTI_USER,
                    "room_count": count,
                    "listen_port": desired.config.get("listen_port", DEFAULT_CALL_PORT),
                    "max_sessions_per_user": desired.config.get("max_sessions_per_user", 1),
                    "max_workers_per_session": desired.config.get(
                        "max_workers_per_session",
                        max(4, count),
                    ),
                })
                desired.config.setdefault("obfs_password", gen_token(32))
                session_group = self.creator.create(CreatorSessionRequest(
                    provider="vk",
                    consumer="calls",
                    lifetime="managed",
                    count=count,
                    previous_tokens=tuple(self.runtime.load_native_join_tokens()),
                ))
                room_links = [endpoint.uri.strip() for endpoint in session_group.endpoints]
                if (
                    len(room_links) != count
                    or any(not link or len(link) > 2048 for link in room_links)
                    or len(set(room_links)) != count
                ):
                    raise RuntimeError("VK creator returned an incomplete Calls room pool")
                self.creator.commit(session_group)
            else:
                desired.config["mode"] = CALL_MODE_P2P
                session_group = self.creator.create(CreatorSessionRequest(
                    provider="vk",
                    consumer="calls",
                    lifetime="transient",
                ))
                join_link = session_group.endpoints[0].uri
                if not join_link:
                    raise RuntimeError("VK creator returned no join link")
                self.runtime.write_native_join_link(join_link)
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
            if managed:
                if not self.runtime.singbox_running():
                    raise RuntimeError("Hydracore multi-user listener is not running")
                try:
                    self.creator.finalize(session_group)
                    finalized = True
                except Exception as exc:
                    close_error = str(exc) or exc.__class__.__name__
            elif not self.runtime.wait_main_join(join_link):
                raise TimeoutError("main Sing-Box did not join the new VK call")
            result = ServiceResult(
                True,
                value={
                    "operation": "rotate" if rotate else "enable",
                    "profile": "admin",
                    "mode": CALL_MODE_MULTI_USER if managed else CALL_MODE_P2P,
                    "rooms": len(session_group.endpoints),
                },
            )
        except Exception as exc:
            if managed and session_group is not None and not finalized:
                try:
                    self.creator.rollback(session_group)
                except Exception:
                    pass
            self._restore_native_transition(state, snapshot, previous_link)
            result = failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            try:
                if session_group is not None and not managed:
                    self.creator.close(session_group)
            except Exception as exc:
                close_error = str(exc) or exc.__class__.__name__
            finally:
                self._end_operation(lease)
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
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            try:
                if purge_link:
                    self.runtime.remove_native_join_link()
                return ServiceResult(True, value={"changed": False})
            finally:
                self._end_operation(lease)
        snapshot = copy.deepcopy(state)
        mode = call_mode(state)
        pool_snapshot = None
        try:
            if mode == CALL_MODE_MULTI_USER:
                pool_snapshot = self.runtime.snapshot_native_pool()
                stopped, message = self.creator.stop_managed("vk", "calls")
                if not stopped:
                    raise RuntimeError(message)
            if not self.protocols.disable(state, "calls"):
                raise RuntimeError(
                    self.last_apply_error() or "failed to disable native VK Calls",
                )
            if purge_link:
                self.runtime.remove_native_join_link()
            return ServiceResult(True, value={"changed": True})
        except Exception as exc:
            if pool_snapshot is not None:
                try:
                    self.runtime.restore_native_pool(pool_snapshot)
                except Exception:
                    pass
            self._restore_native_transition(
                state,
                snapshot,
                self.runtime.load_native_join_link(),
            )
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._end_operation(lease)

    def uninstall_native_vk(self, state: AppState) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        snapshot = copy.deepcopy(state)
        previous_link = self.runtime.load_native_join_link()
        desired = state.protocols.get("calls")
        was_installed = bool(desired and desired.installed)
        mode = call_mode(state)
        pool_snapshot = None
        try:
            if mode == CALL_MODE_MULTI_USER:
                pool_snapshot = self.runtime.snapshot_native_pool()
                stopped, message = self.creator.stop_managed("vk", "calls")
                if not stopped:
                    raise RuntimeError(message)
            if was_installed and not self.protocols.uninstall(state, "calls"):
                raise RuntimeError(
                    self.last_apply_error() or "failed to uninstall native VK Calls",
                )
            if mode == CALL_MODE_MULTI_USER:
                removed, message = self.runtime.uninstall_native_pool()
                if not removed:
                    raise RuntimeError(message)
            self.runtime.remove_native_join_link()
            return ServiceResult(
                True,
                value={"changed": bool(was_installed or previous_link)},
            )
        except Exception as exc:
            if pool_snapshot is not None:
                try:
                    self.runtime.restore_native_pool(pool_snapshot)
                except Exception:
                    pass
            self._restore_native_transition(state, snapshot, previous_link)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._end_operation(lease)

    def native_client_profile(self, state: AppState) -> CallClientProfile:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            raise ValueError("native VK Calls are not enabled")
        mode = call_mode(state)
        links = self.runtime.load_native_join_links() if mode == CALL_MODE_MULTI_USER else []
        link = links[0] if links else self.runtime.load_native_join_link()
        if not link:
            raise RuntimeError("native VK call join link is unavailable")
        if mode == CALL_MODE_MULTI_USER:
            user = next((item for item in state.users if not item.blocked), None)
            if user is None:
                raise ValueError("native VK Calls have no active user")
            outbound = multi_user_outbound(user, state, links)
            profile_name = f"HYDRA Calls · VK · {user.email}"
        else:
            outbound = {
                "type": "call",
                "tag": "call-vk-out",
                "platform": "vk",
                "read_buffer": int(desired.config.get("read_buffer", 32768)),
                "join_link": link,
            }
            profile_name = "HYDRA Calls · VK · admin"
        config = {
            "log": {"level": "info", "timestamp": True},
            "dns": {"servers": [{"type": "local", "tag": "default"}]},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
            }],
            "outbounds": [outbound],
            "route": {
                "final": "call-vk-out",
                "default_domain_resolver": "default",
                "auto_detect_interface": True,
            },
        }
        return CallClientProfile(
            name=profile_name,
            platform="vk",
            join_link=link,
            config=json.dumps(config, ensure_ascii=False, indent=2),
            join_links=tuple(links),
        )


__all__ = [
    "CallClientProfile",
    "CallOperationLock",
    "CallOperations",
    "CallsRuntime",
    "CallsService",
    "CallsStatus",
    "UnavailableCallOperations",
]
