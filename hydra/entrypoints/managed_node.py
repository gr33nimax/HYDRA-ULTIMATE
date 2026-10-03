"""Node-only management API and bounded SSH enrollment entrypoint."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from hydra.bootstrap import production_managed_node_agent
from hydra.core.host import HOST
from hydra.services.managed_nodes.enrollment import apply_management_firewall
from hydra.services.managed_nodes.identity import (
    persist_management_identity,
    validate_certificate_identity,
)
from hydra.services.managed_nodes.transport import ManagedNodeServer
from hydra.utils.commands import redact_text

IDENTITY_ROOT = Path("/etc/hydra/managed-node")
MAX_PROVISION_REQUEST_BYTES = 16 * 1024
MAX_PUBLIC_CERTIFICATE_BYTES = 64 * 1024
_CONTROL_UNIT = "hydra-managed-node.service"
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def read_request(stream, *, maximum: int = MAX_PROVISION_REQUEST_BYTES) -> dict[str, Any]:
    raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("managed-node request exceeds the size limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("managed-node request is invalid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("managed-node request must be an object")
    return document


def _ssh_peer_address() -> str:
    fields = os.environ.get("SSH_CONNECTION", "").split()
    if len(fields) != 4:
        raise ValueError("SSH peer address is unavailable")
    try:
        source = str(ipaddress.ip_address(fields[0]))
        if not 1 <= int(fields[1]) <= 65535:
            raise ValueError
        ipaddress.ip_address(fields[2])
        if not 1 <= int(fields[3]) <= 65535:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError("SSH peer information is invalid") from exc
    return source


def provision_from_ssh(document: dict[str, Any], *, host=HOST, root: Path = IDENTITY_ROOT) -> None:
    expected = {"action", "node_id", "address", "control_port", "source_ip", "base_certificate"}
    if set(document) != expected or document.get("action") != "provision":
        raise ValueError("management identity request has an invalid shape")
    node_id = document["node_id"]
    address = str(ipaddress.ip_address(document["address"]))
    port = document["control_port"]
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id) or type(port) is not int or not 1024 <= port <= 65535 or port == 22:
        raise ValueError("management identity request is invalid")
    source = _ssh_peer_address()
    if str(ipaddress.ip_address(document["source_ip"])) != source:
        raise ValueError("SSH source address does not match the planned firewall source")
    certificate = document["base_certificate"]
    if not isinstance(certificate, str) or len(certificate) > MAX_PUBLIC_CERTIFICATE_BYTES:
        raise ValueError("base management certificate is invalid or too large")
    try:
        cert_bytes = certificate.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base management certificate must be ASCII PEM") from exc
    validate_certificate_identity(cert_bytes, node_id="base", role="client")
    persist_management_identity(
        host=host,
        root=root,
        node_id=node_id,
        address=address,
        control_port=port,
        base_certificate=cert_bytes,
        allowed_source_ips=[source],
    )
    apply_management_firewall(host=host, source_ip=source, control_port=port, node_id=node_id)
    for action in ("enable", "start"):
        result = host.systemd(action, _CONTROL_UNIT, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"managed-node service {action} failed")


def read_public_certificate(
    document: dict[str, Any],
    *,
    host=HOST,
    root: Path = IDENTITY_ROOT,
) -> bytes:
    if set(document) != {"action", "node_id", "address"} or document.get("action") != "read-public-certificate":
        raise ValueError("public certificate request has an invalid shape")
    node_id = document["node_id"]
    address = str(ipaddress.ip_address(document["address"]))
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise ValueError("public certificate identity is invalid")
    # Read only the bounded public certificate; never enumerate or open its private directory.
    path = root / "node.crt"
    certificate = host.read_bytes(path, max_bytes=MAX_PUBLIC_CERTIFICATE_BYTES)
    validate_certificate_identity(certificate, node_id=node_id, role="server", address=address)
    return certificate


def _provision_main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        raise ValueError("managed-node enrollment requires root")
    provision_from_ssh(read_request(sys.stdin.buffer))
    return 0


def remove_node_firewall(*, host=HOST, root: Path = IDENTITY_ROOT) -> None:
    config_path = root / "identity.json"
    if config_path.is_symlink():
        raise ValueError("management identity configuration is unsafe")
    if not config_path.exists():
        return
    from hydra.services.managed_nodes.identity import load_management_identity

    identity = load_management_identity(root, host=host)
    from hydra.services.managed_nodes.enrollment import remove_management_firewall

    remove_management_firewall(
        host=host,
        node_id=identity.node_id,
        allowed_source_ips=identity.allowed_source_ips,
    )


def _read_certificate_main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        raise ValueError("public node certificate read requires root")
    certificate = read_public_certificate(read_request(sys.stdin.buffer))
    sys.stdout.buffer.write(certificate)
    return 0


def _serve_main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        raise ValueError("managed-node control service requires root")
    from hydra.services.managed_nodes.identity import load_management_identity

    identity = load_management_identity(IDENTITY_ROOT, host=HOST)
    apply_management_firewall(
        host=HOST,
        source_ip=identity.allowed_source_ips[0],
        control_port=identity.control_port,
        node_id=identity.node_id,
    )
    server = ManagedNodeServer(
        identity,
        production_managed_node_agent(identity),
        bind_host="::" if ipaddress.ip_address(identity.address).version == 6 else "0.0.0.0",
    ).start()
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    try:
        stopping.wait()
    finally:
        server.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hydra-managed-node")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--provision", action="store_true")
    actions.add_argument("--read-public-certificate", action="store_true")
    actions.add_argument("--remove-firewall", action="store_true")
    actions.add_argument("--serve", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.provision:
            return _provision_main()
        if arguments.read_public_certificate:
            return _read_certificate_main()
        if arguments.remove_firewall:
            if os.name != "nt" and os.geteuid() != 0:
                raise ValueError("management firewall cleanup requires root")
            remove_node_firewall()
            return 0
        return _serve_main()
    except Exception as exc:
        print(f"managed-node operation failed: {redact_text(str(exc))[:160]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "IDENTITY_ROOT", "MAX_PROVISION_REQUEST_BYTES", "MAX_PUBLIC_CERTIFICATE_BYTES",
    "main", "provision_from_ssh", "read_public_certificate", "read_request",
    "remove_node_firewall",
]
