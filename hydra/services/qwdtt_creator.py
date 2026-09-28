"""qWDTT-owned lifecycle for managed creator session groups."""
from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol

from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_creator_models import (
    DEFAULT_QWDTT_REFRESH_INTERVAL,
    DEFAULT_QWDTT_ROOM_COUNT,
    MAX_QWDTT_REFRESH_INTERVAL,
    MIN_QWDTT_REFRESH_INTERVAL,
    get_creator_consumer,
    normalize_qwdtt_room_count,
)
from hydra.core.state_models import AppState
from hydra.services.configuration import restore_state_in_place
from hydra.services.creator_sessions import (
    CreatorSessionGroup,
    CreatorSessionRequest,
    CreatorSessions,
)
from hydra.services.plugin_actions import PluginActions


QWDTT_AUTO_FLAG = "sync_headless_creator_vk_qwdtt_enabled"


class QwdttCreatorRuntime(Protocol):
    def install_creator(self) -> tuple[bool, str]: ...
    def read_creator_hashes(self) -> list[str]: ...
    def pool_metadata(self) -> dict[str, object]: ...
    def snapshot_creator_pool(self) -> object: ...
    def restore_creator_pool(self, snapshot: object) -> None: ...
    def snapshot_legacy_creator(self) -> object: ...
    def cleanup_legacy_creator(self) -> tuple[bool, str]: ...
    def restore_legacy_creator(self, snapshot: object) -> None: ...
    def uninstall_creator_pool(self) -> tuple[bool, str]: ...


class QwdttCreatorOperations(Protocol):
    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def refresh_qwdtt_pool(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> ServiceResult: ...
    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def uninstall_qwdtt_pool(self, state: AppState) -> ServiceResult: ...
    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult: ...
    def set_qwdtt_room_count(self, state: AppState, count: int) -> ServiceResult: ...
    def set_qwdtt_auto_refresh(self, state: AppState, enabled: bool) -> ServiceResult: ...
    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool: ...
    def room_count(self, state: AppState) -> int: ...
    def refresh_interval(self, state: AppState) -> int: ...
    def actual_room_count(self) -> int: ...
    def refreshed_at(self) -> str: ...


class OperationLease(Protocol):
    def release(self) -> None: ...


class OperationLock(Protocol):
    def try_acquire(self) -> OperationLease | None: ...


@dataclass(frozen=True)
class NoopOperationLease:
    def release(self) -> None:
        return None


@dataclass(frozen=True)
class NoopOperationLock:
    def try_acquire(self) -> OperationLease:
        return NoopOperationLease()


@dataclass
class QwdttCreatorService:
    """Own qWDTT desired state, artifacts, rotation and rollback."""

    sessions: CreatorSessions
    runtime: QwdttCreatorRuntime
    plugin_actions: PluginActions
    save_state: Callable[[AppState], None]
    operation_lock: OperationLock = field(default_factory=NoopOperationLock)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        snapshot = copy.deepcopy(state)
        group: CreatorSessionGroup | None = None
        previous_artifact: str | None = None
        legacy_snapshot = None
        legacy_mutated = False
        committed = False
        try:
            wdtt = state.protocols.get("wdtt")
            if wdtt is None or not wdtt.enabled:
                raise ValueError("qWDTT must be enabled before creating its call pool")
            config = self._ensure_config(state)
            count = self.room_count(state)
            legacy = bool(config.get("legacy_creator_reinstall_required", False))
            if legacy:
                legacy_snapshot = self.runtime.snapshot_legacy_creator()
            installed, message = self.runtime.install_creator()
            if not installed:
                raise RuntimeError(message)
            group = self._create_group(state, count)
            previous_artifact = self._publish_artifact(state, group)
            self.sessions.commit(group)
            config.update({"provider": "vk", "pool_enabled": True, "room_count": count})
            if legacy:
                legacy_mutated = True
                cleaned, cleanup_message = self.runtime.cleanup_legacy_creator()
                if not cleaned:
                    raise RuntimeError(cleanup_message)
                config.pop("legacy_creator_reinstall_required", None)
            self.save_state(state)
            committed = True
            warning = self._finalize(group)
            value = {"message": message, "call_count": len(group.endpoints)}
            if warning:
                value["cleanup_warning"] = warning
            return ServiceResult(True, value=value)
        except Exception as exc:
            if committed:
                return ServiceResult(True, value={"cleanup_warning": str(exc)})
            rollback_errors = self._rollback_setup(
                state,
                snapshot,
                group,
                previous_artifact,
                legacy_snapshot if legacy_mutated else None,
            )
            return self._failure_with_rollback(exc, rollback_errors)
        finally:
            try:
                lease.release()
            finally:
                self._lock.release()

    def refresh_qwdtt_pool(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        group: CreatorSessionGroup | None = None
        previous_artifact: str | None = None
        committed = False
        try:
            if not self._config(state).get("pool_enabled", False):
                raise ValueError("qWDTT creator pool is disabled")
            if not forced and not self.qwdtt_pool_due(state):
                return ServiceResult(True, value={"changed": False, "message": "pool is fresh"})
            group = self._create_group(state, self.room_count(state))
            previous_artifact = self._publish_artifact(state, group)
            self.sessions.commit(group)
            committed = True
            warning = self._finalize(group)
            value = {"changed": True, "call_count": len(group.endpoints)}
            if warning:
                value["cleanup_warning"] = warning
            return ServiceResult(True, value=value)
        except Exception as exc:
            if committed:
                return ServiceResult(True, value={"changed": True, "cleanup_warning": str(exc)})
            rollback_errors = self._rollback_group(group, previous_artifact)
            return self._failure_with_rollback(exc, rollback_errors)
        finally:
            try:
                lease.release()
            finally:
                self._lock.release()

    def _create_group(self, state: AppState, count: int) -> CreatorSessionGroup:
        previous = tuple(self.runtime.read_creator_hashes())
        return self.sessions.create(CreatorSessionRequest(
            provider=str(self._config(state).get("provider", "vk")),
            consumer="qwdtt",
            lifetime="managed",
            count=count,
            previous_tokens=previous,
        ))

    def _publish_artifact(
        self,
        state: AppState,
        group: CreatorSessionGroup,
    ) -> str:
        published = self.plugin_actions.execute(
            "wdtt",
            "update_call_pool_artifact",
            state=state,
            hashes=[endpoint.token for endpoint in group.endpoints],
        )
        if not isinstance(published, dict) or published.get("ok") is not True:
            raise RuntimeError("WDTT returned an invalid call-pool result")
        return str(published.get("previous_link", ""))

    def _finalize(self, group: CreatorSessionGroup) -> str:
        try:
            self.sessions.finalize(group)
            return ""
        except Exception as exc:
            return str(exc) or exc.__class__.__name__

    def _rollback_setup(
        self,
        state: AppState,
        snapshot: AppState,
        group: CreatorSessionGroup | None,
        previous_artifact: str | None,
        legacy_snapshot: object | None,
    ) -> list[str]:
        errors = self._rollback_group(group, previous_artifact)
        if legacy_snapshot is not None:
            self._attempt(errors, self.runtime.restore_legacy_creator, legacy_snapshot)
        restore_state_in_place(state, snapshot)
        self._attempt(errors, self.save_state, state)
        return errors

    def _rollback_group(
        self,
        group: CreatorSessionGroup | None,
        previous_artifact: str | None,
    ) -> list[str]:
        errors: list[str] = []
        if previous_artifact is not None:
            self._attempt(errors, self._restore_artifact, previous_artifact)
        if group is not None:
            self._attempt(errors, self.sessions.rollback, group)
        return errors

    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult:
        lease, failure = self._begin_operation()
        if failure is not None:
            return failure
        state_snapshot = copy.deepcopy(state)
        runtime_snapshot = None
        previous_artifact: str | None = None
        try:
            runtime_snapshot = self.runtime.snapshot_creator_pool()
            ok, message = self.sessions.stop_managed(
                str(self._config(state).get("provider", "vk")),
                "qwdtt",
            )
            if not ok:
                raise RuntimeError(message)
            cleared = self.plugin_actions.execute("wdtt", "clear_call_pool_artifact")
            if not isinstance(cleared, dict) or cleared.get("ok") is not True:
                raise RuntimeError("WDTT returned an invalid call-pool cleanup result")
            previous_artifact = str(cleared.get("previous_link", ""))
            self._ensure_config(state)["pool_enabled"] = False
            self.save_state(state)
            return ServiceResult(True, value={"message": message})
        except Exception as exc:
            errors: list[str] = []
            restore_state_in_place(state, state_snapshot)
            if runtime_snapshot is not None:
                self._attempt(errors, self.runtime.restore_creator_pool, runtime_snapshot)
            if previous_artifact is not None:
                self._attempt(errors, self._restore_artifact, previous_artifact)
            self._attempt(errors, self.save_state, state)
            return self._failure_with_rollback(exc, errors)
        finally:
            try:
                lease.release()
            finally:
                self._lock.release()

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
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult:
        try:
            if (
                type(seconds) is not int
                or not MIN_QWDTT_REFRESH_INTERVAL <= seconds <= MAX_QWDTT_REFRESH_INTERVAL
            ):
                raise ValueError("refresh interval must be between 1 and 24 hours")
            self._ensure_config(state)["refresh_interval_seconds"] = seconds
            self.save_state(state)
            return ServiceResult(True, value={"seconds": seconds})
        except Exception as exc:
            return failed_result(exc)

    def set_qwdtt_room_count(self, state: AppState, count: int) -> ServiceResult:
        try:
            normalized = normalize_qwdtt_room_count(count)
            self._ensure_config(state)["room_count"] = normalized
            self.save_state(state)
            return ServiceResult(True, value={"room_count": normalized})
        except Exception as exc:
            return failed_result(exc)

    def set_qwdtt_auto_refresh(self, state: AppState, enabled: bool) -> ServiceResult:
        try:
            if type(enabled) is not bool:
                raise ValueError("auto refresh flag must be boolean")
            state.install[QWDTT_AUTO_FLAG] = enabled
            self.save_state(state)
            return ServiceResult(True, value={"enabled": enabled})
        except Exception as exc:
            return failed_result(exc)

    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool:
        if forced:
            return True
        if not self._config(state).get("pool_enabled", False):
            return False
        metadata = self.runtime.pool_metadata()
        stored_hashes = metadata.get("hashes", [])
        live_hashes = self.runtime.read_creator_hashes()
        if live_hashes and live_hashes != stored_hashes:
            return True
        if metadata.get("room_count") != self.room_count(state):
            return True
        refreshed_at = metadata.get("refreshed_at")
        if not refreshed_at:
            return True
        try:
            refreshed = datetime.fromisoformat(str(refreshed_at))
            if refreshed.tzinfo is None:
                refreshed = refreshed.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - refreshed).total_seconds()
            return elapsed >= self.refresh_interval(state)
        except (TypeError, ValueError):
            return True

    def room_count(self, state: AppState) -> int:
        return normalize_qwdtt_room_count(
            self._config(state).get("room_count", DEFAULT_QWDTT_ROOM_COUNT),
        )

    def refresh_interval(self, state: AppState) -> int:
        return int(self._config(state).get(
            "refresh_interval_seconds",
            DEFAULT_QWDTT_REFRESH_INTERVAL,
        ))

    def actual_room_count(self) -> int:
        return len(set(self.runtime.read_creator_hashes()))

    def refreshed_at(self) -> str:
        return str(self.runtime.pool_metadata().get("refreshed_at", ""))

    @staticmethod
    def _config(state: AppState) -> dict:
        return state.headless_creator.consumers.get("qwdtt", {})

    @staticmethod
    def _ensure_config(state: AppState) -> dict:
        return get_creator_consumer(state.headless_creator, "qwdtt")

    def _restore_artifact(self, link: str) -> None:
        restored = self.plugin_actions.execute(
            "wdtt",
            "update_call_pool_artifact",
            restore_link=link,
        )
        if not isinstance(restored, dict) or restored.get("ok") is not True:
            raise RuntimeError("WDTT rejected call-pool rollback")

    @staticmethod
    def _attempt(errors: list[str], callback: Callable, *args: object) -> None:
        try:
            callback(*args)
        except Exception as exc:
            errors.append(str(exc) or exc.__class__.__name__)

    @staticmethod
    def _failure_with_rollback(exc: Exception, errors: list[str]) -> ServiceResult:
        if errors:
            exc = RuntimeError(f"{exc}; rollback errors: {'; '.join(errors)}")
        return failed_result(exc, fallback=ErrorCode.OPERATION_FAILED)

    def _begin_operation(self) -> tuple[OperationLease | None, ServiceResult | None]:
        if not self._lock.acquire(blocking=False):
            return None, self._conflict()
        try:
            lease = self.operation_lock.try_acquire()
        except Exception as exc:
            self._lock.release()
            return None, failed_result(exc, fallback=ErrorCode.HOST_OPERATION)
        if lease is None:
            self._lock.release()
            return None, self._conflict()
        return lease, None

    @staticmethod
    def _conflict() -> ServiceResult:
        return failed_result(
            RuntimeError("another qWDTT creator operation is already running"),
            fallback=ErrorCode.CONFLICT,
        )


__all__ = [
    "QWDTT_AUTO_FLAG",
    "NoopOperationLock",
    "OperationLease",
    "OperationLock",
    "QwdttCreatorOperations",
    "QwdttCreatorRuntime",
    "QwdttCreatorService",
]
