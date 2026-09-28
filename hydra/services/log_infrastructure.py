"""Local-host implementation of the operational log port."""
from __future__ import annotations

import select
import subprocess
from collections import deque
from pathlib import Path
from typing import Any, Callable

from hydra.services.logs import (
    LogOperations,
    LogReadResult,
    LogSourceInfo,
    LogStream,
)
from hydra.utils.commands import redact_text


class ProcessLogStream(LogStream):
    """Own a child process and expose only bounded line-oriented operations."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process

    def read_line(self, timeout_seconds: float = 0.25) -> str | None:
        output = self._process.stdout
        if output is None:
            return None
        ready, _, _ = select.select([output], [], [], timeout_seconds)
        if not ready:
            return None
        line = output.readline()
        return redact_text(line.rstrip("\n")) if line else None

    def running(self) -> bool:
        return self._process.poll() is None

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._process.kill()


class HostLogOperations(LogOperations):
    """Read files and journald through explicitly injected host capabilities."""

    def __init__(
        self,
        *,
        run_command: Callable[..., Any],
        popen_command: Callable[..., subprocess.Popen[str]],
        unit_active: Callable[[str], bool],
        unit_known: Callable[[str], bool],
    ) -> None:
        self._run_command = run_command
        self._popen_command = popen_command
        self._unit_active = unit_active
        self._unit_known = unit_known

    def read(
        self,
        source_type: str,
        source: str,
        num_lines: int,
    ) -> LogReadResult:
        if num_lines <= 0:
            raise ValueError("num_lines must be positive")
        if source_type == "file":
            return self._read_file(Path(source), num_lines)
        if source_type != "journal":
            raise ValueError(f"unsupported log source type: {source_type}")
        return self._read_journal(source, num_lines)

    @staticmethod
    def _read_file(path: Path, num_lines: int) -> LogReadResult:
        if not path.exists():
            return LogReadResult(message="Файл ещё не создан.")
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = tuple(
                    redact_text(line.rstrip("\n"))
                    for line in deque(handle, maxlen=num_lines)
                )
        except OSError as exc:
            return LogReadResult(message=f"Ошибка чтения файла: {exc}")
        return LogReadResult(lines=lines)

    def _read_journal(self, unit: str, num_lines: int) -> LogReadResult:
        try:
            result = self._run_command(
                [
                    "journalctl",
                    "-u",
                    unit,
                    "-n",
                    str(num_lines),
                    "--no-pager",
                    "-o",
                    "short-iso",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return LogReadResult(
                message=f"Не удалось прочитать journalctl: {exc}",
            )

        output = str(result.stdout or "").strip()
        if result.returncode != 0:
            message = str(
                result.stderr
                or output
                or "journalctl завершился с ошибкой",
            ).strip()
            return LogReadResult(message=redact_text(message))
        lines = tuple(
            redact_text(line)
            for line in output.splitlines()
            if line.strip() and line.strip() != "-- No entries --"
        )
        return LogReadResult(
            lines=lines,
            message="" if lines else "В журнале пока нет записей.",
        )

    def source_info(
        self,
        source_type: str,
        source: str,
    ) -> LogSourceInfo:
        if source_type == "file":
            path = Path(source)
            try:
                stat = path.stat()
            except OSError:
                return LogSourceInfo(available=False)
            return LogSourceInfo(
                available=True,
                size_bytes=stat.st_size,
                modified_at=stat.st_mtime,
            )
        if source_type != "journal":
            raise ValueError(f"unsupported log source type: {source_type}")
        loaded = self._unit_known(source)
        return LogSourceInfo(
            available=loaded,
            active=self._unit_active(source),
            loaded=loaded,
        )

    def open_stream(
        self,
        source_type: str,
        source: str,
    ) -> LogStream:
        if source_type == "file":
            if not Path(source).exists():
                raise FileNotFoundError(source)
            command = ["tail", "--follow=name", "--retry", "--lines=0", source]
        elif source_type == "journal":
            command = [
                "journalctl",
                "-u",
                source,
                "-f",
                "-n",
                "0",
                "--no-pager",
                "-o",
                "short-iso",
            ]
        else:
            raise ValueError(f"unsupported log source type: {source_type}")

        process = self._popen_command(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        return ProcessLogStream(process)
