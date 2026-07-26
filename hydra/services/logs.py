"""Transport-neutral port for reading and following operational logs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class LogReadResult:
    """A bounded log read returned to presentation adapters."""

    lines: tuple[str, ...] = ()
    message: str = ""


@dataclass(frozen=True)
class LogSourceInfo:
    """Metadata needed to render a file or journal source status."""

    available: bool
    size_bytes: int | None = None
    modified_at: float | None = None
    active: bool = False
    loaded: bool = False


class LogStream(Protocol):
    """Incremental stream without exposing a subprocess to the UI layer."""

    def read_line(self, timeout_seconds: float = 0.25) -> str | None: ...

    def running(self) -> bool: ...

    def close(self) -> None: ...


class LogOperations(Protocol):
    """Log capabilities consumed by CLI/TUI/Telegram adapters."""

    def read(
        self,
        source_type: str,
        source: str,
        num_lines: int,
    ) -> LogReadResult: ...

    def source_info(
        self,
        source_type: str,
        source: str,
    ) -> LogSourceInfo: ...

    def open_stream(
        self,
        source_type: str,
        source: str,
    ) -> LogStream: ...


class UnavailableLogOperations:
    """Default for applications assembled without host log access."""

    def __getattr__(self, name: str):
        raise RuntimeError(f"log operation is not configured: {name}")
