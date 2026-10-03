"""Minimal SSH_ASKPASS helper; the password is fetched over a scoped loopback socket."""

from __future__ import annotations

import os
import socket

SOCKET_ENV = "HYDRA_MANAGED_ASKPASS_SOCKET"
TOKEN_ENV = "HYDRA_MANAGED_ASKPASS_TOKEN"
MAX_PASSWORD_BYTES = 4096


def request_password(environment: dict[str, str] | None = None) -> str:
    env = os.environ if environment is None else environment
    address = env.get(SOCKET_ENV, "")
    token = env.get(TOKEN_ENV, "")
    host, separator, port_text = address.rpartition(":")
    if not separator or host != "127.0.0.1" or len(token) != 64 or not token.isalnum():
        raise ValueError("SSH password channel is unavailable")
    try:
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ValueError("SSH password channel address is invalid") from exc
    connection = socket.create_connection((host, port), timeout=5)
    try:
        connection.sendall(token.encode("ascii") + b"\n")
        chunks = bytearray()
        while len(chunks) <= MAX_PASSWORD_BYTES:
            part = connection.recv(min(1024, MAX_PASSWORD_BYTES + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if not chunks or len(chunks) > MAX_PASSWORD_BYTES or not chunks.endswith(b"\n"):
            raise ValueError("SSH password channel returned an invalid response")
        return bytes(chunks[:-1]).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("SSH password channel request failed") from exc
    finally:
        connection.close()


def main() -> int:
    try:
        password = request_password()
    except Exception:
        return 1
    import sys

    sys.stdout.write(password)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "request_password"]
