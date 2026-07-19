"""Safe, bounded execution of external commands."""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from hydra.core.errors import HostOperationError


class CommandError(HostOperationError):
    """A command failed or exceeded its deadline."""


DEFAULT_TIMEOUT = 30
_SECRET_ARG = re.compile(r"(?i)(token|password|secret|private[_-]?key|authorization)=([^\s]+)")
_SECRET_TEXT = re.compile(
    r"(?i)(token|password|secret|private[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)


def redact_text(value: str) -> str:
    """Remove common credential forms from human-readable log messages."""
    return _SECRET_TEXT.sub(r"\1\2<redacted>", str(value))


def redact_command(args: Sequence[object]) -> str:
    values = [str(value) for value in args]
    return " ".join(redact_text(_SECRET_ARG.sub(r"\1=<redacted>", value)) for value in values)


def run(
    args: Sequence[object],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    check: bool = False,
    input: bytes | str | None = None,
    text: bool = False,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run an argv command without a shell and with a bounded runtime."""
    argv = [str(arg) for arg in args]
    try:
        result = subprocess.run(
            argv,
            input=input,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"Command timed out after {timeout:g}s: {redact_command(argv)}") from exc
    except OSError as exc:
        raise CommandError(f"Could not execute {redact_command(argv)}: {exc}") from exc
    if check and result.returncode != 0:
        detail = result.stderr if text else (result.stderr or b"").decode(errors="replace")
        raise CommandError(f"{redact_command(argv)} failed ({result.returncode}): {detail.strip() or 'unknown error'}")
    return result


def popen(args: Sequence[object], *, timeout: float = DEFAULT_TIMEOUT, **kwargs) -> subprocess.Popen:
    """Start an argv command; streaming callers enforce the attached deadline."""
    argv = [str(arg) for arg in args]
    kwargs.setdefault("env", os.environ.copy())
    process = subprocess.Popen(argv, **kwargs)
    process._hydra_timeout = timeout  # type: ignore[attr-defined]
    process._hydra_command = redact_command(argv)  # type: ignore[attr-defined]
    return process
