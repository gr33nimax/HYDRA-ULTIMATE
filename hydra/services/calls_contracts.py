"""Typed application contracts shared by native Calls adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState


CALLS_POOL_AUTO_FLAG = "sync_calls_vk_pool_enabled"


@dataclass(frozen=True)
class CallsStatus:
    feature_supported: bool
    creator_installed: bool
    cookies_ready: bool
    native_enabled: bool
    native_link_ready: bool
    native_running: bool
    native_mode: str = "vk_parasite"
    room_count: int = 0
    pool_auto_refresh: bool = False
    pool_refresh_interval_seconds: int = 86_400
    pool_refreshed_at: str = ""
    external_probe_checked_at: str = ""
    external_probe_outcome: str = ""
    external_probe_confirmation_pending: bool = False

    @property
    def native_pool_ready(self) -> bool:
        """Return readiness using the managed-pool terminology."""
        return self.native_link_ready

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CallClientProfile:
    name: str
    platform: str
    join_link: str
    config: str
    join_links: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class CallOperations(Protocol):
    def status(self, state: AppState) -> CallsStatus: ...
    def enable_native_vk(self, state: AppState) -> ServiceResult: ...
    def reinstall_native_vk(self, state: AppState) -> ServiceResult: ...
    def rotate_native_vk(self, state: AppState) -> ServiceResult: ...
    def replace_native_vk_slot(self, state: AppState, slot: int) -> ServiceResult: ...
    def disable_native_vk(self, state: AppState, *, purge_link: bool = False) -> ServiceResult: ...
    def uninstall_native_vk(self, state: AppState) -> ServiceResult: ...
    def native_client_profile(self, state: AppState) -> CallClientProfile: ...
    def set_workers(self, state: AppState, count: int) -> ServiceResult: ...
    def import_vk_cookies(self, state: AppState, source_path: str) -> ServiceResult: ...
    def set_pool_auto_refresh(self, state: AppState, enabled: bool) -> ServiceResult: ...
    def set_pool_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult: ...
    def pool_rotation_due(self, state: AppState, *, forced: bool = False) -> bool: ...
    def run_health(self, state: AppState, *, forced: bool = False) -> ServiceResult: ...


class CallsProtocolOperations(Protocol):
    def activate(self, state: AppState, name: str) -> bool: ...
    def enable(self, state: AppState, name: str) -> bool: ...
    def disable(self, state: AppState, name: str) -> bool: ...
    def uninstall(self, state: AppState, name: str) -> bool: ...


class UnavailableCallOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Calls operation is not configured: {name}")


class CallsRuntime(Protocol):
    def vk_parasite_supported(self) -> bool: ...
    def load_native_join_links(self) -> list[str]: ...
    def load_native_join_tokens(self) -> list[str]: ...
    def pool_metadata(self) -> dict[str, object]: ...
    def snapshot_native_pool(self) -> object: ...
    def restore_native_pool(self, snapshot: object) -> None: ...
    def ensure_creator_installed(self) -> tuple[bool, str]: ...
    def import_vk_cookies(self, source_path: Path) -> None: ...
    def stage_native_slot(self, slot: int) -> list[str]: ...
    def finalize_native_slot(self) -> None: ...
    def rollback_native_slot(self) -> None: ...
    def uninstall_native_pool(self) -> tuple[bool, str]: ...
    def remove_native_join_link(self) -> None: ...
    def singbox_running(self) -> bool: ...


class CallOperationLease(Protocol):
    def release(self) -> None: ...


class CallOperationLock(Protocol):
    def try_acquire(self) -> CallOperationLease | None: ...


class NoopCallOperationLock:
    def try_acquire(self) -> CallOperationLease:
        return self

    def release(self) -> None:
        return None


__all__ = [
    "CALLS_POOL_AUTO_FLAG",
    "CallClientProfile",
    "CallOperationLease",
    "CallOperationLock",
    "CallOperations",
    "CallsProtocolOperations",
    "CallsRuntime",
    "CallsStatus",
    "NoopCallOperationLock",
    "UnavailableCallOperations",
]
