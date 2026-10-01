"""One-time local channel that lets OpenSSH read a password without ever seeing it.

OpenSSH has no supported way to receive a password as an argument or on stdin, and
HYDRA must not put a password into argv, the environment, a plaintext file or a log.
The supported mechanism is ``SSH_ASKPASS``: ssh executes a program and reads the
password from its stdout. This module owns the program and the channel between it and
the process that holds the secret:

* a loopback socket on an ephemeral port accepts one connection;
* the helper proves itself with a random token, which is not the secret;
* the secret is written once per request and never stored anywhere.

The channel is scoped: it is created for one enrollment, only the local user can
reach it, and it is closed as soon as the enrollment ends. A missing or refused
channel makes ssh fail authentication instead of silently succeeding.
"""

from __future__ import annotations

import logging
import os
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

ASKPASS_SOCKET_VAR = "HYDRA_ASKPASS_SOCKET"
ASKPASS_TOKEN_VAR = "HYDRA_ASKPASS_TOKEN"
ASKPASS_TIMEOUT = 10.0
MAX_REQUESTS = 16

# The helper is started by ssh, not by this process, so it inherits neither the
# launcher's sys.path nor a guaranteed working directory. The project root is therefore
# baked into PYTHONPATH: without it a base whose launcher added the root to sys.path
# only in-process cannot answer ssh's prompt at all.
_HELPER_SOURCE = """#!/bin/sh
export PYTHONPATH={root}${{PYTHONPATH:+:$PYTHONPATH}}
exec {interpreter} -m hydra.entrypoints.ssh_askpass "$@"
"""


class SshAuthError(RuntimeError):
    """The password channel could not be prepared safely."""


@dataclass
class SshPasswordAuth:
    """Serve one enrollment's password to OpenSSH over a scoped local socket."""

    password: str
    _server: socket.socket | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _directory: tempfile.TemporaryDirectory | None = field(default=None, repr=False)
    _helper: Path | None = field(default=None, repr=False)
    _token: str = field(default="", repr=False)
    _serving: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.password, str) or not self.password:
            raise SshAuthError("SSH password must be a non-empty string")
        if len(self.password) > 4096:
            raise SshAuthError("SSH password exceeds the supported length")
        self._token = secrets.token_hex(32)

    def __enter__(self) -> "SshPasswordAuth":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def start(self) -> "SshPasswordAuth":
        if self._serving:
            return self
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(8)
            server.settimeout(ASKPASS_TIMEOUT)
        except OSError as exc:
            server.close()
            raise SshAuthError(f"password channel is unavailable: {type(exc).__name__}") from exc
        self._server = server
        self._thread = threading.Thread(target=self._serve, name="hydra-askpass", daemon=True)
        self._thread.start()
        self._serving = True
        return self

    def _serve(self) -> None:
        server = self._server
        if server is None:
            return
        served = 0
        while served < MAX_REQUESTS:
            try:
                connection, _ = server.accept()
            except (OSError, TimeoutError):
                return
            except Exception:
                return
            try:
                with connection:
                    connection.settimeout(ASKPASS_TIMEOUT)
                    request = connection.recv(4096).decode("utf-8", "replace").strip()
                    if request == self._token:
                        connection.sendall(self.password.encode("utf-8") + b"\n")
            except Exception:
                continue
            finally:
                served += 1

    def environment(self, *, interpreter: str | None = None) -> dict[str, str]:
        """Environment for one ssh invocation; it carries the token, never the secret."""
        if not self._serving:
            raise SshAuthError("password channel is not running")
        helper = self._helper_path(interpreter)
        environment = dict(os.environ)
        environment["SSH_ASKPASS"] = str(helper)
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment[ASKPASS_SOCKET_VAR] = self._socket_address()
        environment[ASKPASS_TOKEN_VAR] = self._token
        # ssh only consults askpass when it believes there is no terminal to use.
        environment.pop("SSH_TTY", None)
        environment.setdefault("DISPLAY", ":0")
        return environment

    def _socket_address(self) -> str:
        server = self._server
        if server is None:
            raise SshAuthError("password channel is not running")
        host, port = server.getsockname()[:2]
        return f"{host}:{port}"

    def _helper_path(self, interpreter: str | None) -> Path:
        if self._helper is not None:
            return self._helper
        self._directory = tempfile.TemporaryDirectory(prefix="hydra-askpass-")
        path = Path(self._directory.name) / "askpass.sh"
        path.write_text(
            _HELPER_SOURCE.format(
                root=shlex.quote(str(_package_root())),
                interpreter=shlex.quote(interpreter or sys.executable),
            ),
            encoding="utf-8",
        )
        path.chmod(stat.S_IRWXU)
        self._helper = path
        return path

    def close(self) -> None:
        self._serving = False
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError as exc:
                _LOGGER.debug("askpass channel close failed: %s", type(exc).__name__)
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)
        directory, self._directory = self._directory, None
        if directory is not None:
            directory.cleanup()
        self._helper = None
        self._token = ""


def run_askpass() -> int:
    """Entrypoint used by OpenSSH: print the password the channel hands over."""
    address = os.environ.get(ASKPASS_SOCKET_VAR, "")
    token = os.environ.get(ASKPASS_TOKEN_VAR, "")
    if not address or not token or ":" not in address:
        return 1
    host, _, port_text = address.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return 1
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.settimeout(ASKPASS_TIMEOUT)
        client.connect((host, port))
        client.sendall(token.encode("utf-8") + b"\n")
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) > 4096:
                return 1
    except (OSError, TimeoutError):
        return 1
    finally:
        client.close()
    secret = b"".join(chunks)
    if not secret:
        return 1
    sys.stdout.write(secret.decode("utf-8", "replace"))
    sys.stdout.flush()
    return 0


def _package_root() -> Path:
    """The directory that holds the ``hydra`` package, for the helper's PYTHONPATH."""
    import hydra

    module = getattr(hydra, "__file__", "") or ""
    if not module:
        raise SshAuthError("the hydra package location is unknown")
    return Path(module).resolve().parent.parent


def ssh_password_auth(password: str | None) -> SshPasswordAuth | None:
    """Build the channel only when a password was actually supplied."""
    if not password:
        return None
    return SshPasswordAuth(password)


def askpass_environment(auth: SshPasswordAuth | None, *, interpreter: str | None = None) -> dict[str, str] | None:
    """Environment for an ssh call that must read the password; None when there is none."""
    if auth is None:
        return None
    return auth.environment(interpreter=interpreter)


def password_available(auth: SshPasswordAuth | None) -> bool:
    """True when a password channel will answer ssh's askpass call."""
    return auth is not None


def subprocess_available() -> bool:
    """A guard for tests and for hosts where OpenSSH cannot be driven this way."""
    return hasattr(subprocess, "run")


__all__ = [
    "ASKPASS_SOCKET_VAR",
    "ASKPASS_TOKEN_VAR",
    "SshAuthError",
    "SshPasswordAuth",
    "askpass_environment",
    "password_available",
    "run_askpass",
    "ssh_password_auth",
]
