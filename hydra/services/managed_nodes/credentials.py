"""Protected management key storage and scoped SSH password channels."""

from __future__ import annotations

import os
import secrets
import shlex
import socket
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.services.managed_nodes.askpass import SOCKET_ENV, TOKEN_ENV
from hydra.services.managed_nodes.identity import (
    create_certificate_pair,
    validate_certificate_identity,
    validate_key_pair,
)

_MAX_PASSWORD = 4096
_ASKPASS_SOURCE = "#!/bin/sh\nexport PYTHONPATH={root}${{PYTHONPATH:+:$PYTHONPATH}}\nexec {interpreter} -m hydra.services.managed_nodes.askpass\n"


class SshAuthError(RuntimeError):
    """The scoped OpenSSH askpass channel could not be used safely."""


@dataclass
class SshPasswordChannel:
    """Serve repeated password prompts until explicit close; never persist the secret."""

    password: str = field(repr=False)
    _server: socket.socket | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _directory: tempfile.TemporaryDirectory | None = field(default=None, init=False, repr=False)
    _helper: Path | None = field(default=None, init=False, repr=False)
    _token: str = field(default="", init=False, repr=False)
    _open: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.password, str)
            or not self.password
            or len(self.password.encode("utf-8")) > _MAX_PASSWORD
            or any(char in self.password for char in "\r\n\0")
        ):
            raise SshAuthError("SSH password must be 1..4096 UTF-8 bytes without line breaks")
        self._token = secrets.token_hex(32)

    def __enter__(self) -> "SshPasswordChannel":
        return self.start()

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._open

    def start(self) -> "SshPasswordChannel":
        if self._open:
            return self
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(8)
            server.settimeout(0.25)
        except OSError as exc:
            server.close()
            raise SshAuthError(f"SSH password channel unavailable: {type(exc).__name__}") from exc
        self._server = server
        self._open = True
        self._thread = threading.Thread(target=self._serve, name="managed-node-askpass", daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        server = self._server
        while self._open and server is not None:
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if address[0] != "127.0.0.1":
                    continue
                with connection:
                    connection.settimeout(2.0)
                    request = connection.recv(256).decode("ascii", "replace").strip()
                    if request == self._token and self._open:
                        connection.sendall(self.password.encode("utf-8") + b"\n")
            except OSError:
                continue

    def environment(self, *, interpreter: str | None = None) -> dict[str, str]:
        if not self._open or self._server is None:
            raise SshAuthError("SSH password channel is closed")
        helper = self._helper_path(interpreter or sys.executable)
        env = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "LANG", "LC_ALL")
            if key in os.environ
        }
        env["SSH_ASKPASS"] = str(helper)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = os.environ.get("DISPLAY", ":0")
        env[SOCKET_ENV] = self._socket_address()
        env[TOKEN_ENV] = self._token
        return env

    def _helper_path(self, interpreter: str) -> Path:
        if self._helper is not None:
            return self._helper
        import hydra

        package_file = getattr(hydra, "__file__", None)
        if not package_file:
            raise SshAuthError("HYDRA package path is unavailable")
        package_root = Path(package_file).resolve().parent.parent
        self._directory = tempfile.TemporaryDirectory(prefix="hydra-managed-askpass-")
        helper = Path(self._directory.name) / "askpass.sh"
        source = _ASKPASS_SOURCE.format(
            root=shlex.quote(str(package_root)),
            interpreter=shlex.quote(interpreter),
        )
        helper.write_text(source, encoding="utf-8")
        helper.chmod(stat.S_IRWXU)
        # The script contains paths only; the password and channel token stay in memory/env.
        self._helper = helper
        return helper

    def _socket_address(self) -> str:
        if self._server is None:
            raise SshAuthError("SSH password channel is closed")
        address, port = self._server.getsockname()[:2]
        return f"{address}:{port}"

    def close(self) -> None:
        self._open = False
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)
        directory, self._directory = self._directory, None
        if directory is not None:
            directory.cleanup()
        self._helper = None
        self._token = ""
        self.password = ""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(is_open={self._open})"


@dataclass(frozen=True)
class ManagementClientFiles:
    certificate: Path
    private_key: Path
    server_certificate: Path | None = None


class ManagementCredentialStore:
    """Keep per-node client private keys outside state with a scoped cleanup path."""

    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("management credential root must be absolute")
        self._host = host
        self._root = root

    def ensure_client_identity(self, identity_ref: str) -> bytes:
        cert_path, key_path, _ = self._paths(identity_ref)
        if cert_path.is_symlink() or key_path.is_symlink():
            raise ValueError("management credentials contain an unsafe symbolic link")
        if cert_path.exists() and key_path.exists():
            certificate = self._host.read_bytes(cert_path, max_bytes=64 * 1024)
            private_key = self._host.read_bytes(key_path, max_bytes=64 * 1024)
            validate_certificate_identity(certificate, node_id="base", role="client")
            validate_key_pair(certificate, private_key)
            self._check_private_mode(key_path)
            return certificate
        if cert_path.exists() or key_path.exists():
            raise ValueError("partial management credentials require explicit recovery")
        certificate, private_key = create_certificate_pair("base", role="client")
        self._host.ensure_directory(cert_path.parent, mode=0o700)
        self._host.atomic_write(cert_path, certificate, mode=0o600, durable=True)
        self._host.atomic_write(key_path, private_key, mode=0o600, durable=True)
        return certificate

    def store_server_certificate(self, identity_ref: str, certificate: bytes, *, node_id: str, address: str) -> Path:
        validate_certificate_identity(certificate, node_id=node_id, role="server", address=address)
        cert_path, key_path, server_path = self._paths(identity_ref)
        if not cert_path.is_file() or not key_path.is_file():
            raise ValueError("base management credentials are unavailable")
        if server_path.is_symlink():
            raise ValueError("management server certificate path is unsafe")
        if server_path.exists():
            existing = self._host.read_bytes(server_path, max_bytes=64 * 1024)
            if existing != certificate:
                raise ValueError("pinned management server identity changed; explicit rotation is required")
            return server_path
        self._host.atomic_write(server_path, certificate, mode=0o600, durable=True)
        return server_path

    def read_server_certificate(self, identity_ref: str) -> bytes | None:
        cert_path, key_path, server_path = self._paths(identity_ref)
        for path in (cert_path, key_path, server_path):
            if path.is_symlink():
                raise ValueError("management credentials contain an unsafe symbolic link")
        if not cert_path.is_file() or not key_path.is_file() or not server_path.is_file():
            return None
        certificate = self._host.read_bytes(cert_path, max_bytes=64 * 1024)
        private_key = self._host.read_bytes(key_path, max_bytes=64 * 1024)
        validate_certificate_identity(certificate, node_id="base", role="client")
        validate_key_pair(certificate, private_key)
        self._check_private_mode(key_path)
        return self._host.read_bytes(server_path, max_bytes=64 * 1024)

    def client_files(self, identity_ref: str) -> ManagementClientFiles:
        cert_path, key_path, server_path = self._paths(identity_ref)
        for path in (cert_path, key_path, server_path):
            if path.is_symlink():
                raise ValueError("management credentials contain an unsafe symbolic link")
        if not cert_path.is_file() or not key_path.is_file() or not server_path.is_file():
            raise ValueError("management credentials are unavailable")
        certificate = self._host.read_bytes(cert_path, max_bytes=64 * 1024)
        private_key = self._host.read_bytes(key_path, max_bytes=64 * 1024)
        validate_certificate_identity(certificate, node_id="base", role="client")
        validate_key_pair(certificate, private_key)
        self._check_private_mode(key_path)
        self._host.read_bytes(server_path, max_bytes=64 * 1024)
        return ManagementClientFiles(cert_path, key_path, server_path)

    def cleanup(self, identity_ref: str) -> None:
        paths = self._paths(identity_ref)
        for path in paths:
            if path.is_symlink():
                raise ValueError("refusing to clean a symbolic-link credential")
        for path in paths:
            self._host.remove_file(path, missing_ok=True)

    @staticmethod
    def _check_private_mode(path: Path) -> None:
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError("management private key permissions are unsafe")

    def _paths(self, identity_ref: str) -> tuple[Path, Path, Path]:
        parts = identity_ref.split("/") if isinstance(identity_ref, str) else []
        if not parts or any(
            part in {"", ".", ".."}
            or not all(char.isascii() and (char.isalnum() or char in "._-") for char in part)
            for part in parts
        ):
            raise ValueError("management identity reference is invalid")
        directory = self._root.joinpath(*parts[:-1])
        if not directory.is_relative_to(self._root):
            raise ValueError("management identity reference escapes credential root")
        stem = parts[-1]
        return directory / f"{stem}.client.crt", directory / f"{stem}.client.key", directory / f"{stem}.server.crt"


__all__ = [
    "ManagementClientFiles", "ManagementCredentialStore", "SshAuthError",
    "SshPasswordChannel",
]
