"""Typed errors crossing HYDRA's host, configuration and plugin boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class HydraError(RuntimeError):
    """Base class for expected HYDRA operational failures."""


class HostOperationError(HydraError):
    """A bounded command or privileged host operation failed."""


class ConfigurationError(HydraError):
    """Configuration could not be generated, validated or applied."""


class PluginError(ConfigurationError):
    """A plugin lifecycle operation failed."""


class RestoreError(HydraError):
    """A backup could not be validated or restored safely."""


class ErrorCode(str, Enum):
    """Stable machine-readable categories exposed by application adapters."""

    INVALID_INPUT = "invalid_input"
    HOST_OPERATION = "host_operation"
    CONFIGURATION = "configuration"
    PLUGIN = "plugin"
    RESTORE = "restore"
    CONFLICT = "conflict"
    OPERATION_FAILED = "operation_failed"
    INTERNAL = "internal"


@dataclass(frozen=True)
class ApplicationError:
    """Normalized error payload shared by CLI, TUI and future transports."""

    code: ErrorCode
    message: str
    retryable: bool = False
    exception_type: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "message": self.message,
            "retryable": self.retryable,
        }


@dataclass(frozen=True)
class ServiceResult:
    """Result envelope that keeps legacy bool semantics via ``bool(result)``."""

    ok: bool
    value: object = None
    error: ApplicationError | None = None

    def __bool__(self) -> bool:
        return self.ok

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": self.ok}
        if self.value is not None:
            payload["value"] = self.value
        if self.error is not None:
            payload["error"] = self.error.as_dict()
        return payload


def normalize_error(exc: BaseException, *, fallback: ErrorCode = ErrorCode.INTERNAL) -> ApplicationError:
    """Map domain exceptions to a stable error code without exposing internals."""
    if isinstance(exc, HostOperationError):
        code = ErrorCode.HOST_OPERATION
    elif isinstance(exc, PluginError):
        code = ErrorCode.PLUGIN
    elif isinstance(exc, RestoreError):
        code = ErrorCode.RESTORE
    elif isinstance(exc, ConfigurationError):
        code = ErrorCode.CONFIGURATION
    elif isinstance(exc, (ValueError, TypeError)):
        code = ErrorCode.INVALID_INPUT
    else:
        code = fallback
    return ApplicationError(
        code=code,
        message=str(exc) or exc.__class__.__name__,
        retryable=code in {ErrorCode.HOST_OPERATION, ErrorCode.OPERATION_FAILED},
        exception_type=exc.__class__.__name__,
    )


def failed_result(exc: BaseException, *, fallback: ErrorCode = ErrorCode.INTERNAL) -> ServiceResult:
    return ServiceResult(False, error=normalize_error(exc, fallback=fallback))
