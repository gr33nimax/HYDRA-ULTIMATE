"""Application use-cases for native Sing-Box Calls."""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass, field
from typing import Callable

from hydra.contracts.calls_configuration import (
    CALL_MODE_VK_PARASITE,
    DEFAULT_CALL_PORT,
    DEFAULT_ROOM_COUNT,
    MAX_JOIN_LINKS,
    MAX_WORKERS,
    call_mode,
    vk_parasite_outbound,
    public_endpoint,
)
from hydra.core.calls_credentials import user_password
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
from hydra.utils.crypto import gen_token
from hydra.utils.net import public_ip


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

    def _vk_parasite_supported(self) -> bool:
        probe = getattr(self.runtime, "vk_parasite_supported", None)
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
        enabled = bool(desired and desired.enabled)
        mode = call_mode(state)
        links = self.runtime.load_native_join_links()
        pool_ready = bool(links)
        creator_status = self.creator.availability("vk")
        return CallsStatus(
            feature_supported=self._vk_parasite_supported(),
            creator_installed=creator_status.installed,
            cookies_ready=creator_status.credentials_ready,
            native_enabled=enabled,
            native_link_ready=pool_ready,
            native_running=bool(enabled and pool_ready and self.runtime.singbox_running()),
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
        if state.kernel.provider != KERNEL_HYDRACORE:
            self._end_operation(lease)
            return failed_result(
                RuntimeError(
                    "native VK Calls require the Hydracore kernel; "
                    "stock Sing-Box Extended is not supported"
                ),
                fallback=ErrorCode.OPERATION_FAILED,
            )
        if not self._vk_parasite_supported():
            self._end_operation(lease)
            return failed_result(
                RuntimeError(
                    "installed Hydracore does not expose the exact "
                    "call_vk_parasite wire-v9 recovery capability contract"
                ),
                fallback=ErrorCode.OPERATION_FAILED,
            )
        try:
            call_mode(state)
        except ValueError as exc:
            self._end_operation(lease)
            return failed_result(exc)
        snapshot = copy.deepcopy(state)
        session_group: CreatorSessionGroup | None = None
        close_error = ""
        finalized = False
        try:
            installer = getattr(self.runtime, "ensure_creator_installed", None)
            if callable(installer):
                installed, install_message = installer()
                if not installed:
                    raise RuntimeError(install_message)
            desired = get_protocol(state, "calls")
            count = desired.config.get("room_count", DEFAULT_ROOM_COUNT)
            if type(count) is not int or not 1 <= count <= MAX_JOIN_LINKS:
                raise ValueError("Calls room_count must be between 1 and 4")
            desired.config.update({
                "mode": CALL_MODE_VK_PARASITE,
                "room_count": count,
                "listen_port": desired.config.get("listen_port", DEFAULT_CALL_PORT),
                "max_sessions_per_user": desired.config.get("max_sessions_per_user", 1),
                "max_workers_per_session": MAX_WORKERS,
                "workers": MAX_WORKERS,
                "public_endpoint": public_endpoint(state, public_ip),
            })
            desired.config.pop("read_buffer", None)
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
            if not self.runtime.singbox_running():
                raise RuntimeError("Hydracore VK parasite listener is not running")
            try:
                self.creator.finalize(session_group)
                finalized = True
            except Exception as exc:
                close_error = str(exc) or exc.__class__.__name__
            result = ServiceResult(
                True,
                value={
                    "operation": "rotate" if rotate else "enable",
                    "profile": "admin",
                    "mode": CALL_MODE_VK_PARASITE,
                    "rooms": len(session_group.endpoints),
                },
            )
        except Exception as exc:
            if session_group is not None and not finalized:
                try:
                    self.creator.rollback(session_group)
                except Exception:
                    pass
            self._restore_native_transition(state, snapshot)
            result = failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
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
    ) -> None:
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
        pool_snapshot = None
        try:
            call_mode(state)
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
            self._restore_native_transition(state, snapshot)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._end_operation(lease)

    def uninstall_native_vk(self, state: AppState) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        snapshot = copy.deepcopy(state)
        desired = state.protocols.get("calls")
        was_installed = bool(desired and desired.installed)
        pool_snapshot = None
        try:
            call_mode(state)
            pool_snapshot = self.runtime.snapshot_native_pool()
            stopped, message = self.creator.stop_managed("vk", "calls")
            if not stopped:
                raise RuntimeError(message)
            if was_installed and not self.protocols.uninstall(state, "calls"):
                raise RuntimeError(
                    self.last_apply_error() or "failed to uninstall native VK Calls",
                )
            removed, message = self.runtime.uninstall_native_pool()
            if not removed:
                raise RuntimeError(message)
            self.runtime.remove_native_join_link()
            return ServiceResult(
                True,
                value={"changed": bool(was_installed or pool_snapshot)},
            )
        except Exception as exc:
            if pool_snapshot is not None:
                try:
                    self.runtime.restore_native_pool(pool_snapshot)
                except Exception:
                    pass
            self._restore_native_transition(state, snapshot)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._end_operation(lease)

    def native_client_profile(self, state: AppState) -> CallClientProfile:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            raise ValueError("native VK Calls are not enabled")
        call_mode(state)
        if state.kernel.provider != KERNEL_HYDRACORE or not self._vk_parasite_supported():
            raise RuntimeError("native VK Calls require exact Hydracore VK parasite support")
        links = self.runtime.load_native_join_links()
        if not links:
            raise RuntimeError("native VK Calls room pool is unavailable")
        user = next((item for item in state.users if not item.blocked), None)
        if user is None:
            raise ValueError("native VK Calls have no active user")
        server_address = public_endpoint(state, public_ip)
        outbound = vk_parasite_outbound(
            user,
            state,
            links,
            user_password,
            server_address=server_address,
        )
        profile_name = "Hydra VK Tunnel"
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
            join_link=links[0],
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
