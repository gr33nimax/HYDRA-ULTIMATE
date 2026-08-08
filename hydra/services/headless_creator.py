"""Provider administration and compatibility facade for creator consumers."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping, Protocol

from hydra.contracts import BackupResource
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_models import AppState
from hydra.services.qwdtt_creator import (
    QWDTT_AUTO_FLAG,
    QwdttCreatorOperations,
)


HEADLESS_CREATOR_BACKUP_RESOURCES = (
    BackupResource("/etc/hydra/cookiesvk", "tree", owner="headless_creator"),
    BackupResource("/var/lib/hydra/headless-creator", "tree", owner="headless_creator"),
    BackupResource(
        "/etc/systemd/system/hydra-headless-creator-vk@.service",
        "file",
        owner="headless_creator",
    ),
)


class CreatorProviderAdmin(Protocol):
    def creator_installed(self) -> bool: ...
    def creator_credentials_path(self) -> str: ...
    def creator_credentials_ready(self) -> bool: ...
    def install_creator(self) -> tuple[bool, str]: ...
    def uninstall_creator(self) -> tuple[bool, str]: ...
    def validate_credentials(self) -> list[dict[str, str]]: ...
    def forget_credentials(self) -> None: ...


@dataclass(frozen=True)
class CreatorProviderStatus:
    name: str
    installed: bool
    credentials_path: str
    credentials_ready: bool


@dataclass(frozen=True)
class HeadlessCreatorStatus:
    installed: bool
    cookies_path: str
    cookies_ready: bool
    providers: tuple[str, ...]
    provider_statuses: tuple[CreatorProviderStatus, ...]
    vk_qwdtt_pool_enabled: bool
    vk_qwdtt_call_count: int
    vk_qwdtt_room_count: int
    vk_qwdtt_refreshed_at: str
    vk_qwdtt_refresh_interval_seconds: int
    legacy_reinstall_required: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class HeadlessCreatorOperations(QwdttCreatorOperations, Protocol):
    def status(self, state: AppState) -> HeadlessCreatorStatus: ...
    def install(self, state: AppState) -> ServiceResult: ...
    def uninstall(self, state: AppState) -> ServiceResult: ...
    def install_provider(self, state: AppState, provider: str) -> ServiceResult: ...
    def uninstall_provider(self, state: AppState, provider: str) -> ServiceResult: ...
    def validate_vk_credentials(self, state: AppState) -> ServiceResult: ...
    def forget_vk_credentials(self, state: AppState) -> ServiceResult: ...


class UnavailableHeadlessCreatorOperations:
    def __getattr__(self, name: str):
        raise RuntimeError(f"Headless Creator operation is not configured: {name}")


@dataclass(frozen=True)
class HeadlessCreatorService:
    """Compose provider administration with consumer-owned qWDTT use-cases."""

    providers: Mapping[str, CreatorProviderAdmin]
    qwdtt: QwdttCreatorOperations

    def status(self, state: AppState) -> HeadlessCreatorStatus:
        provider_statuses = tuple(
            self._provider_status(name, runtime)
            for name, runtime in sorted(self.providers.items())
        )
        vk = next(status for status in provider_statuses if status.name == "vk")
        qwdtt = state.headless_creator.consumers.get("qwdtt", {})
        return HeadlessCreatorStatus(
            installed=vk.installed,
            cookies_path=vk.credentials_path,
            cookies_ready=vk.credentials_ready,
            providers=tuple(status.name for status in provider_statuses),
            provider_statuses=provider_statuses,
            vk_qwdtt_pool_enabled=bool(qwdtt.get("pool_enabled", False)),
            vk_qwdtt_call_count=self.qwdtt.actual_room_count(),
            vk_qwdtt_room_count=self.qwdtt.room_count(state),
            vk_qwdtt_refreshed_at=self.qwdtt.refreshed_at(),
            vk_qwdtt_refresh_interval_seconds=self.qwdtt.refresh_interval(state),
            legacy_reinstall_required=bool(
                qwdtt.get("legacy_creator_reinstall_required", False),
            ),
        )

    @staticmethod
    def _provider_status(
        name: str,
        runtime: CreatorProviderAdmin,
    ) -> CreatorProviderStatus:
        return CreatorProviderStatus(
            name=name,
            installed=runtime.creator_installed(),
            credentials_path=runtime.creator_credentials_path(),
            credentials_ready=runtime.creator_credentials_ready(),
        )

    def install(self, state: AppState) -> ServiceResult:
        return self.install_provider(state, "vk")

    def install_provider(self, state: AppState, provider: str) -> ServiceResult:
        del state
        try:
            ok, message = self._provider(provider).install_creator()
            if not ok:
                raise RuntimeError(message)
            return ServiceResult(True, value={"provider": provider, "message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def uninstall(self, state: AppState) -> ServiceResult:
        return self.uninstall_provider(state, "vk")

    def uninstall_provider(self, state: AppState, provider: str) -> ServiceResult:
        calls = state.protocols.get("calls")
        qwdtt = state.headless_creator.consumers.get("qwdtt", {})
        if provider == "vk" and calls and calls.enabled:
            return failed_result(ValueError("disable native Calls before removing creator"))
        if provider == qwdtt.get("provider", "vk") and qwdtt.get("pool_enabled", False):
            return failed_result(ValueError("remove the qWDTT pool before removing creator"))
        try:
            ok, message = self._provider(provider).uninstall_creator()
            if not ok:
                raise RuntimeError(message)
            return ServiceResult(True, value={"provider": provider, "message": message})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def validate_vk_credentials(self, state: AppState) -> ServiceResult:
        del state
        try:
            self._provider("vk").validate_credentials()
            return ServiceResult(True, value={"valid": True})
        except Exception as exc:
            return failed_result(exc)

    def forget_vk_credentials(self, state: AppState) -> ServiceResult:
        calls = state.protocols.get("calls")
        qwdtt = state.headless_creator.consumers.get("qwdtt", {})
        if calls and calls.enabled:
            return failed_result(ValueError("disable native VK Calls first"))
        if qwdtt.get("provider", "vk") == "vk" and qwdtt.get("pool_enabled", False):
            return failed_result(ValueError("uninstall the qWDTT call pool first"))
        try:
            self._provider("vk").forget_credentials()
            return ServiceResult(True, value={"removed": True})
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.HOST_OPERATION)

    def setup_qwdtt_pool(self, state: AppState) -> ServiceResult:
        return self.qwdtt.setup_qwdtt_pool(state)

    def refresh_qwdtt_pool(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> ServiceResult:
        return self.qwdtt.refresh_qwdtt_pool(state, forced=forced)

    def stop_qwdtt_pool(self, state: AppState) -> ServiceResult:
        return self.qwdtt.stop_qwdtt_pool(state)

    def uninstall_qwdtt_pool(self, state: AppState) -> ServiceResult:
        return self.qwdtt.uninstall_qwdtt_pool(state)

    def set_qwdtt_refresh_interval(self, state: AppState, seconds: int) -> ServiceResult:
        return self.qwdtt.set_qwdtt_refresh_interval(state, seconds)

    def set_qwdtt_room_count(self, state: AppState, count: int) -> ServiceResult:
        return self.qwdtt.set_qwdtt_room_count(state, count)

    def set_qwdtt_auto_refresh(self, state: AppState, enabled: bool) -> ServiceResult:
        return self.qwdtt.set_qwdtt_auto_refresh(state, enabled)

    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool:
        return self.qwdtt.qwdtt_pool_due(state, forced=forced)

    def _provider(self, name: str) -> CreatorProviderAdmin:
        normalized = str(name or "").strip().lower()
        try:
            return self.providers[normalized]
        except KeyError as exc:
            raise ValueError(f"unknown creator provider: {normalized}") from exc


__all__ = [
    "CreatorProviderAdmin",
    "CreatorProviderStatus",
    "HeadlessCreatorOperations",
    "HEADLESS_CREATOR_BACKUP_RESOURCES",
    "HeadlessCreatorService",
    "HeadlessCreatorStatus",
    "QWDTT_AUTO_FLAG",
    "UnavailableHeadlessCreatorOperations",
]
