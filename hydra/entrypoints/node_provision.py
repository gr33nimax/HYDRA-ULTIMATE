"""SSH-only root entrypoint for first-time node identity provisioning."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from dataclasses import dataclass

from hydra.bootstrap import production_node_uninstall
from hydra.core.host import HOST
from hydra.core.node_identity import load_node_identity
from hydra.services.nodes.provision import (
    provision_node_identity,
    revoke_node_control_identity,
    rotate_node_control_identity,
)

_NODE_CONTROL_UNIT = "hydra-node-control.service"
_MAX_PROVISION_REQUEST_BYTES = 16 * 1024
_ALLOWED_REQUEST_KEYS = {
    "node_id",
    "base_url",
    "control_address",
    "control_port",
    "base_certificate",
}


@dataclass(frozen=True)
class _ProvisionRequest:
    action: str
    node_id: str
    base_url: str = ""
    control_address: str = ""
    control_port: int = 0
    base_certificate: bytes = b""


def _source_address() -> str:
    fields = os.environ.get("SSH_CONNECTION", "").split()
    if len(fields) != 4:
        raise ValueError("SSH peer information is unavailable")
    address = ipaddress.ip_address(fields[0])
    if not 1 <= int(fields[1]) <= 65535:
        raise ValueError("SSH peer port is invalid")
    ipaddress.ip_address(fields[2])
    if not 1 <= int(fields[3]) <= 65535:
        raise ValueError("SSH server port is invalid")
    return str(address)


def _read_request() -> _ProvisionRequest:
    raw = sys.stdin.read(_MAX_PROVISION_REQUEST_BYTES + 1)
    if len(raw.encode("utf-8")) > _MAX_PROVISION_REQUEST_BYTES:
        raise ValueError("provisioning request is too large")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("provisioning request is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("provisioning request has an invalid shape")
    action = payload.get("action", "provision")
    if action not in {"provision", "rotate", "revoke", "uninstall"}:
        raise ValueError("provisioning request has an unsupported action")
    if action in {"revoke", "uninstall"}:
        if set(payload) != {"action", "node_id"}:
            raise ValueError("management request has an invalid shape")
        node_id = payload.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("provisioning request node_id must be non-empty text")
        return _ProvisionRequest(action=action, node_id=node_id)
    expected_keys = _ALLOWED_REQUEST_KEYS | ({"action"} if "action" in payload else set())
    if set(payload) != expected_keys:
        raise ValueError("provisioning request has an invalid shape")
    node_id = payload.get("node_id")
    base_url = payload.get("base_url")
    control_address = payload.get("control_address")
    control_port = payload.get("control_port")
    base_certificate = payload.get("base_certificate")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("provisioning request node_id must be non-empty text")
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("provisioning request base_url must be non-empty text")
    if not isinstance(control_address, str) or not control_address:
        raise ValueError("provisioning request control_address must be non-empty text")
    if not isinstance(base_certificate, str) or not base_certificate:
        raise ValueError("provisioning request base_certificate must be non-empty text")
    if type(control_port) is not int:
        raise ValueError("provisioning request control_port must be an integer")
    try:
        certificate_bytes = base_certificate.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base certificate must be ASCII PEM") from exc
    return _ProvisionRequest(action, node_id, base_url, control_address, control_port, certificate_bytes)


def main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        print("Node control management requires root", file=sys.stderr)
        return 2
    failure_label, success_label = "provisioning", "provisioned"
    try:
        request = _read_request()
        if request.action == "revoke":
            failure_label, success_label = "revocation", "revoked"
            revoke_node_control_identity(node_id=request.node_id, host=HOST)
        elif request.action == "uninstall":
            failure_label, success_label = "uninstallation", "uninstalled"
            identity = load_node_identity()
            if identity is None or identity.node_id != request.node_id:
                raise ValueError("node identity does not match the uninstall request")
            production_node_uninstall()
        elif request.action == "rotate":
            failure_label, success_label = "rotation", "rotated"
            rotate_node_control_identity(
                node_id=request.node_id,
                base_url=request.base_url,
                base_ip=_source_address(),
                control_address=request.control_address,
                control_port=request.control_port,
                base_certificate=request.base_certificate,
                host=HOST,
            )
        else:
            provision_node_identity(
                node_id=request.node_id,
                base_url=request.base_url,
                base_ip=_source_address(),
                control_address=request.control_address,
                control_port=request.control_port,
                base_certificate=request.base_certificate,
                host=HOST,
            )
            for action in ("enable", "start"):
                result = HOST.systemd(action, _NODE_CONTROL_UNIT)
                if result.returncode != 0:
                    raise RuntimeError(f"systemd {action} failed")
    except Exception:
        print(f"Node control {failure_label} failed", file=sys.stderr)
        return 2
    if request.action == "uninstall":
        print("Node installation removed")
    else:
        print(f"Node control identity {success_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
