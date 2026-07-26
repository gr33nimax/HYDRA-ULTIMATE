"""Ports for network and host probes used by diagnostic presentation adapters.

The TUI deliberately works with plain values returned by this contract.  URL
openers, sockets, clocks, filesystem reads, and subprocess sentinels belong to
the host adapter in :mod:`hydra.services.diagnostic_infrastructure`.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Protocol


@dataclass(frozen=True)
class HttpProbeResult:
    """Normalized result of one HTTP request."""

    status: int = 0
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    error_kind: str = ""
    error_detail: str = ""

    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")


class DiagnosticOperations(Protocol):
    """Read-only host capabilities needed by the diagnostics UI."""

    @property
    def pipe(self) -> object: ...

    @property
    def devnull(self) -> object: ...

    @property
    def stdout(self) -> object: ...

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        timeout: float = 2.0,
        verify_tls: bool = True,
    ) -> HttpProbeResult: ...

    def resolve_addresses(self, host: str) -> tuple[str, ...]: ...

    def ipv6_available(self) -> bool: ...

    def port_listening(self, port: int) -> bool: ...

    def tcp_connect(self, host: str, port: int, timeout: float) -> bool: ...

    def read_json_file(self, path: str) -> Any: ...

    def path_exists(self, path: str) -> bool: ...

    def which(self, binary: str) -> str | None: ...

    def monotonic(self) -> float: ...

    def wall_time(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...

    def url_hostname(self, url: str) -> str: ...

    def download_speed_mbps(
        self,
        url: str,
        *,
        timeout: float = 3.0,
        duration: float = 4.0,
        chunk_size: int = 65_536,
    ) -> float: ...


class UnavailableDiagnosticOperations:
    """Default for application instances assembled without diagnostic I/O."""

    def __getattr__(self, name: str):
        raise RuntimeError(f"diagnostic operation is not configured: {name}")


_ACTIVE_OPERATIONS: ContextVar[DiagnosticOperations | None] = ContextVar(
    "hydra_diagnostic_operations",
    default=None,
)


def active_diagnostic_operations() -> DiagnosticOperations | None:
    """Return the operations explicitly scoped by the composition adapter."""

    return _ACTIVE_OPERATIONS.get()


@contextmanager
def diagnostic_scope(
    operations: DiagnosticOperations,
) -> Iterator[DiagnosticOperations]:
    """Temporarily bind diagnostic operations for nested legacy collectors."""

    token = _ACTIVE_OPERATIONS.set(operations)
    try:
        yield operations
    finally:
        _ACTIVE_OPERATIONS.reset(token)
