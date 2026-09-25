"""Application use-cases for native Sing-Box Calls."""

from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


CREATOR_OPERATION_ERRORS = (OSError, RuntimeError, ValueError)

from hydra.contracts.calls_configuration import (
    CALL_MODE_VK_PARASITE,
    CALL_COUNT,
    DEFAULT_CALL_PORT,
    call_mode,
    pool_refresh_interval,
    workers as configured_workers,
    vk_parasite_outbound,
    public_endpoint,
)
from hydra.core.calls_credentials import user_password
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_kernel_models import KERNEL_HYDRACORE
from hydra.core.state_models import AppState, get_protocol
from hydra.services.calls_health import CallsProbeStore
from hydra.services.calls_native_transition import run_native_transition
from hydra.services.configuration import restore_state_in_place
from hydra.services.calls_contracts import (
    CALLS_POOL_AUTO_FLAG,
    CallClientProfile,
    CallOperationLease,
    CallOperationLock,
    CallOperations,
    CallsProtocolOperations,
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
from hydra.utils.crypto import gen_token
from hydra.utils.net import public_ip


@dataclass
class CallsService:
    """Coordinate native Call lifecycle using the shared headless creator."""

    runtime: CallsRuntime
    creator: CreatorSessions
    protocols: CallsProtocolOperations
    save_state: Callable[[AppState], None]
    apply_config: Callable[[AppState], bool]
    operation_lock: CallOperationLock = field(default_factory=NoopCallOperationLock)
    last_apply_error: Callable[[], str] = lambda: ""
    probe_store: CallsProbeStore | None = None
    turn_probe: object | None = None
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
        metadata = self.runtime.pool_metadata()
        probe_status = self.probe_store.status(links) if self.probe_store and links else {}
        return CallsStatus(
            feature_supported=self._vk_parasite_supported(),
            creator_installed=creator_status.installed,
            cookies_ready=creator_status.credentials_ready,
            native_enabled=enabled,
            native_link_ready=pool_ready,
            native_running=bool(enabled and pool_ready and self.runtime.singbox_running()),
            native_mode=mode,
            room_count=len(links),
            pool_auto_refresh=bool(
                state.install.get(CALLS_POOL_AUTO_FLAG, False),
            ),
            pool_refresh_interval_seconds=pool_refresh_interval(
                desired.config if desired else {},
            ),
            pool_refreshed_at=str(metadata.get("refreshed_at", "")),
            external_probe_checked_at=str(probe_status.get("last_checked_at", "")),
            external_probe_outcome=str(probe_status.get("last_outcome", "")),
            external_probe_confirmation_pending=bool(probe_status.get("confirmation_pending", False)),
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
        result = self._native_transition(state, rotate=True)
        if result and self.probe_store is not None:
            self.probe_store.reset()
        return result

    def replace_native_vk_slot(self, state: AppState, slot: int) -> ServiceResult:
        """Replace one confirmed-dead room without stopping its three siblings."""
        if not 1 <= slot <= CALL_COUNT:
            return failed_result(ValueError("VK Calls room slot is outside the pool"))
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        snapshot = copy.deepcopy(state)
        staged = False
        try:
            desired = state.protocols.get("calls")
            if desired is None or not desired.enabled:
                raise ValueError("native VK Calls are not enabled")
            links = self.runtime.stage_native_slot(slot)
            staged = True
            if len(links) != CALL_COUNT or len(set(links)) != CALL_COUNT:
                raise RuntimeError("replacement VK room did not preserve a complete pool")
            if not self.apply_config(state):
                raise RuntimeError(self.last_apply_error() or "failed to apply replacement VK room")
            if not self.runtime.singbox_running():
                raise RuntimeError("Hydracore VK parasite listener is not running")
            self.runtime.finalize_native_slot()
            staged = False
            return ServiceResult(True, value={"operation": "replace", "slot": slot})
        except (OSError, RuntimeError, ValueError) as exc:
            if staged:
                try:
                    self.runtime.rollback_native_slot()
                except (OSError, RuntimeError, ValueError):
                    pass
            self._restore_native_transition(state, snapshot)
            return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)
        finally:
            self._end_operation(lease)

    def run_health(self, state: AppState, *, forced: bool = False) -> ServiceResult:
        """Run one serialized health decision; external errors never evict a room."""
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            return ServiceResult(True, value={"operation": "health", "status": "disabled"})
        links = self.runtime.load_native_join_links()
        if len(links) != CALL_COUNT:
            return self.rotate_native_vk(state)
        outcome = "fresh"
        confirmation = False
        slot = 0
        if self.probe_store is not None and self.turn_probe is not None:
            lease, failure = self._begin_operation()
            if failure is not None:
                return failure
            try:
                decision = self.probe_store.claim_due(links, now=datetime.now(timezone.utc))
                if decision is not None:
                    result = getattr(self.turn_probe, "verify")(links[decision.slot - 1])
                    outcome = str(getattr(result, "outcome", "error"))
                    self.probe_store.record(links, decision, outcome, now=datetime.now(timezone.utc))
                    confirmation, slot = decision.confirmation, decision.slot
            finally:
                self._end_operation(lease)
        auto_rotation = bool(state.install.get(CALLS_POOL_AUTO_FLAG, False))
        rotation_due = auto_rotation and self.pool_rotation_due(state, forced=forced)
        if confirmation and outcome == "dead":
            return self.rotate_native_vk(state) if rotation_due else self.replace_native_vk_slot(state, slot)
        if rotation_due:
            return self.rotate_native_vk(state)
        return ServiceResult(True, value={"operation": "health", "status": outcome})

    def set_pool_auto_refresh(
        self,
        state: AppState,
        enabled: bool,
    ) -> ServiceResult:
        if type(enabled) is not bool:
            return failed_result(
                ValueError("pool auto refresh flag must be boolean"),
            )
        before = state.install.get(CALLS_POOL_AUTO_FLAG)
        try:
            state.install[CALLS_POOL_AUTO_FLAG] = enabled
            self.save_state(state)
            return ServiceResult(True, value={"enabled": enabled})
        except Exception as exc:
            if before is None:
                state.install.pop(CALLS_POOL_AUTO_FLAG, None)
            else:
                state.install[CALLS_POOL_AUTO_FLAG] = before
            return failed_result(exc)

    def set_pool_refresh_interval(
        self,
        state: AppState,
        seconds: int,
    ) -> ServiceResult:
        desired = state.protocols.get("calls")
        if desired is None or not desired.installed:
            return failed_result(ValueError("native VK Calls are not installed"))
        before = copy.deepcopy(desired.config)
        try:
            desired.config["pool_refresh_interval_seconds"] = seconds
            normalized = pool_refresh_interval(desired.config)
            self.save_state(state)
            return ServiceResult(True, value={"seconds": normalized})
        except Exception as exc:
            desired.config = before
            return failed_result(exc)

    def pool_rotation_due(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> bool:
        desired = state.protocols.get("calls")
        if desired is None or not desired.enabled:
            return False
        if forced or len(self.runtime.load_native_join_links()) != CALL_COUNT:
            return True
        refreshed_at = self.runtime.pool_metadata().get("refreshed_at")
        if not refreshed_at:
            return True
        try:
            refreshed = datetime.fromisoformat(str(refreshed_at))
            if refreshed.tzinfo is None:
                refreshed = refreshed.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - refreshed).total_seconds() >= pool_refresh_interval(desired.config)
        except (TypeError, ValueError):
            return True

    def set_workers(self, state: AppState, count: int) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        desired = get_protocol(state, "calls")
        before = copy.deepcopy(desired.config)
        try:
            desired.config["workers"] = count
            desired.config.pop("max_workers_per_session", None)
            count = configured_workers(desired.config)
            self.save_state(state)
            if desired.enabled and not self.apply_config(state):
                raise RuntimeError(self.last_apply_error() or "failed to apply Calls workers")
            return ServiceResult(True, value={"workers": count})
        except Exception as exc:
            desired.config = before
            try:
                self.save_state(state)
            except Exception:
                pass
            return failed_result(exc)
        finally:
            self._end_operation(lease)

    def import_vk_cookies(self, state: AppState, source_path: str) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        try:
            self.runtime.import_vk_cookies(Path(source_path).expanduser())
            return ServiceResult(True, value={"imported": True})
        except Exception as exc:
            return failed_result(exc)
        finally:
            self._end_operation(lease)

    def _native_transition(self, state: AppState, *, rotate: bool) -> ServiceResult:
        return run_native_transition(self, state, rotate=rotate)

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
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": 1080,
                }
            ],
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
    "CALLS_POOL_AUTO_FLAG",
    "CallClientProfile",
    "CallOperationLock",
    "CallOperations",
    "CallsRuntime",
    "CallsService",
    "CallsStatus",
    "UnavailableCallOperations",
]
