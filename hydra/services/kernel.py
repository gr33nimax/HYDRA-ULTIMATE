"""Application use-case for selecting the managed Sing-Box-compatible core."""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Protocol

from hydra.core.state_kernel_models import KernelConfig, validate_kernel_config
from hydra.core.state_models import AppState
from hydra.services.configuration import restore_state_in_place


@dataclass(frozen=True)
class KernelRuntimeStatus:
    installed: bool
    running: bool = False
    provider: str = "unknown"
    version: str = ""
    capabilities: tuple[str, ...] = ()
    binary_path: str = ""


@dataclass(frozen=True)
class KernelStatus:
    desired_provider: str
    desired_channel: str
    runtime: KernelRuntimeStatus
    drift: bool

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["runtime"] = asdict(self.runtime)
        return payload


@dataclass(frozen=True)
class KernelSwitchResult:
    ok: bool
    changed: bool
    status: KernelStatus
    message: str = ""

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["status"] = self.status.as_dict()
        return payload


class PreparedKernelSwitch(Protocol):
    runtime: KernelRuntimeStatus

    def commit(self) -> None: ...
    def rollback(self) -> None: ...


class KernelRuntimeOperations(Protocol):
    def inspect(self) -> KernelRuntimeStatus: ...

    def prepare_switch(
        self,
        provider: str,
        channel: str,
    ) -> PreparedKernelSwitch: ...


class KernelOperations(Protocol):
    def status(self, state: AppState) -> KernelStatus: ...

    def switch(
        self,
        state: AppState,
        provider: str,
        *,
        channel: str = "stable",
        force: bool = False,
    ) -> KernelSwitchResult: ...


class KernelService:
    """Persist desired selection only after the candidate passed runtime checks."""

    def __init__(self, runtime: KernelRuntimeOperations, *, save_state) -> None:
        self._runtime = runtime
        self._save_state = save_state

    def status(self, state: AppState) -> KernelStatus:
        runtime = self._runtime.inspect()
        return KernelStatus(
            desired_provider=state.kernel.provider,
            desired_channel=state.kernel.channel,
            runtime=runtime,
            drift=bool(
                not runtime.installed
                or runtime.provider != state.kernel.provider
            ),
        )

    def switch(
        self,
        state: AppState,
        provider: str,
        *,
        channel: str = "stable",
        force: bool = False,
    ) -> KernelSwitchResult:
        desired = KernelConfig(provider=provider, channel=channel)
        validate_kernel_config(desired)
        before = copy.deepcopy(state)
        current = self.status(state)
        if (
            not force
            and not current.drift
            and before.kernel.provider == desired.provider
            and before.kernel.channel == desired.channel
        ):
            return KernelSwitchResult(
                True,
                False,
                current,
                "requested kernel is already active",
            )

        prepared = self._runtime.prepare_switch(provider, channel)
        state.kernel = desired
        try:
            self._save_state(state)
        except Exception as persist_error:
            restore_state_in_place(state, before)
            state.revision = before.revision
            try:
                prepared.rollback()
            except Exception as rollback_error:
                raise RuntimeError(
                    "kernel selection was not persisted and runtime rollback failed: "
                    f"{rollback_error}",
                ) from persist_error
            raise
        prepared.commit()
        status = self.status(state)
        return KernelSwitchResult(
            True,
            True,
            status,
            f"kernel switched to {provider}",
        )


class UnavailableKernelOperations:
    def status(self, state: AppState) -> KernelStatus:
        del state
        raise RuntimeError("kernel operations are not configured")

    def switch(self, state: AppState, provider: str, **kwargs) -> KernelSwitchResult:
        del state, provider, kwargs
        raise RuntimeError("kernel operations are not configured")


__all__ = [
    "KernelRuntimeOperations",
    "KernelOperations",
    "KernelRuntimeStatus",
    "KernelService",
    "KernelStatus",
    "KernelSwitchResult",
    "PreparedKernelSwitch",
    "UnavailableKernelOperations",
]
