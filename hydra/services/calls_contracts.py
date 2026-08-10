"""Typed application contracts shared by native Calls adapters."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState


@dataclass(frozen=True)
class CallsStatus:
    feature_supported: bool
    creator_installed: bool
    cookies_ready: bool
    native_enabled: bool
    native_link_ready: bool
    native_running: bool
    native_mode: str = "multi_user"
    room_count: int = 0

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
    def disable_native_vk(self, state: AppState, *, purge_link: bool = False) -> ServiceResult: ...
    def uninstall_native_vk(self, state: AppState) -> ServiceResult: ...
    def native_client_profile(self, state: AppState) -> CallClientProfile: ...
    def set_room_count(self, state: AppState, count: int) -> ServiceResult: ...


class UnavailableCallOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Calls operation is not configured: {name}")


class CallsRuntime(Protocol):
    def multi_user_supported(self) -> bool: ...
    def load_native_join_links(self) -> list[str]: ...
    def load_native_join_tokens(self) -> list[str]: ...
    def snapshot_native_pool(self) -> object: ...
    def restore_native_pool(self, snapshot: object) -> None: ...
    def ensure_creator_installed(self) -> tuple[bool, str]: ...
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
    "CallClientProfile",
    "CallOperationLease",
    "CallOperationLock",
    "CallOperations",
    "CallsRuntime",
    "CallsStatus",
    "NoopCallOperationLock",
    "UnavailableCallOperations",
]
