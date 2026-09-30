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

# Credential-shaped keys. `cookie` and `set-cookie` are here because a session cookie is
# a credential, and `api_key`/`access_token`/`psk` because they are what the transports
# actually accept instead of a password.
_SECRET_KEY = (
    r"(?:token|password|secret|private[_-]?key|authorization|cookie|set-cookie"
    r"|api[_-]?key|access[_-]?token|auth[_-]?token|session[_-]?id|psk|preshared[_-]?key)"
)
# `Authorization: Bearer <token>` hides the scheme as well; masking only "Bearer" left
# the token itself in every log that quoted a failed request.
_AUTH_SCHEME = r"(?:(?:bearer|basic|digest|token)\s+)?"
_SECRET_ARG = re.compile(rf"(?i)({_SECRET_KEY})=([^\s]+)")
_SECRET_TEXT = re.compile(rf"(?i)({_SECRET_KEY})(\s*[:=]\s*)({_AUTH_SCHEME}[^\s,;]+)")
_COOKIE_HEADER = re.compile(r"(?i)\b(cookie|set-cookie)\b\s*[:=]\s*([^\n]+)")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    re.DOTALL,
)
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]+):([^/\s@]+)@")
_VK_CALL_LINK = re.compile(
    r"https://(?:www\.)?vk\.(?:com|ru)/call/join/[^\s\"'<>]+",
    re.IGNORECASE,
)
_QWDTT_LINK = re.compile(r"qwdtt://[^\s]+")


def redact_text(value: str) -> str:
    """Remove common credential forms from human-readable log messages."""
    redacted = _PRIVATE_KEY_BLOCK.sub("<redacted>", str(value))
    redacted = _COOKIE_HEADER.sub(r"\1: <redacted>", redacted)
    redacted = _SECRET_TEXT.sub(r"\1\2<redacted>", redacted)
    redacted = _URL_CREDENTIALS.sub(r"\1\2:<redacted>@", redacted)
    redacted = _VK_CALL_LINK.sub("https://vk.com/call/join/<redacted>", redacted)
    return _QWDTT_LINK.sub("qwdtt://<redacted>", redacted)


def redact_command(args: Sequence[object]) -> str:
    values = [str(value) for value in args]
    return " ".join(redact_text(_SECRET_ARG.sub(r"\1=<redacted>", value)) for value in values)


def bounded_reason(result: object, *, limit: int = 160) -> str:
    """Bounded, redacted first stderr line of a failed command result.

    Operator diagnostics need the real reason (for example which systemd unit
    is invalid) without unbounded host output or leaked credentials.
    """
    text = getattr(result, "stderr", "") or ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    for line in str(text).splitlines():
        cleaned = "".join(character for character in line if character.isprintable()).strip()
        if cleaned:
            return _truncate(redact_text(cleaned), limit)
    return ""


def _truncate(value: str, limit: int) -> str:
    """Cut to ``limit`` without leaving a half-written redaction marker."""
    if len(value) <= limit:
        return value
    truncated = value[:limit]
    marker = "<redacted>"
    for size in range(len(marker) - 1, 0, -1):
        if truncated.endswith(marker[:size]):
            return truncated[:-size]
    return truncated


def run(
    args: Sequence[object],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    check: bool = False,
    input: bytes | str | None = None,
    text: bool = False,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    stdout=None,
    stderr=None,
    encoding: str | None = None,
    errors: str | None = None,
) -> subprocess.CompletedProcess:
    """Run an argv command without a shell and with a bounded runtime."""
    argv = [str(arg) for arg in args]
    if stdout is not None or stderr is not None:
        capture_output = False
    try:
        options = {
            "input": input,
            "capture_output": capture_output,
            "text": text,
            "timeout": timeout,
            "env": env,
            "check": False,
        }
        for key, value in (
            ("stdout", stdout),
            ("stderr", stderr),
            ("cwd", cwd),
            ("encoding", encoding),
            ("errors", errors),
        ):
            if value is not None:
                options[key] = value
        result = subprocess.run(argv, **options)
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
    process = subprocess.Popen(argv, **kwargs)
    process._hydra_timeout = timeout  # type: ignore[attr-defined]
    process._hydra_command = redact_command(argv)  # type: ignore[attr-defined]
    return process
