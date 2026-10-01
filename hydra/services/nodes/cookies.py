"""Bounded per-node VK-cookie upload over pinned SSH, never shell/argv secrets."""

from __future__ import annotations

import json
from pathlib import Path

from hydra.contracts.node_validation import checked_node_id
from hydra.core.host import HostBackend
from hydra.services.nodes.installer import checked_ssh_user, remote_command, ssh_target
from hydra.core.state_nodes import NodeConfig
from hydra.services.headless_creator_infrastructure import normalize_vk_cookies
from hydra.services.nodes.installer import ssh_connection_flags, valid_node_address

MAX_NODE_COOKIE_BYTES = 1024 * 1024


def cookie_request(raw: object) -> tuple[str, list[dict[str, str]]]:
    if not isinstance(raw, dict) or set(raw) != {"node_id", "cookies"}:
        raise ValueError("invalid node cookie request")
    node_id = checked_node_id(raw["node_id"], context="node_id")
    return node_id, normalize_vk_cookies(raw["cookies"])


def load_cookie_file(source_path: str) -> list[dict[str, str]]:
    source = Path(source_path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise ValueError("cookie source must be a regular non-symlink file")
    with source.open("rb") as handle:
        data = handle.read(MAX_NODE_COOKIE_BYTES + 1)
    if len(data) > MAX_NODE_COOKIE_BYTES:
        raise ValueError("cookie source exceeds the supported size")
    try:
        return normalize_vk_cookies(json.loads(data))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ValueError("invalid VK cookies file") from exc


def import_node_vk_cookies(
    node: NodeConfig,
    source_path: str,
    *,
    host: HostBackend,
    known_hosts_root: Path,
    ssh_user: str = "root",
    identity_file: Path | None = None,
) -> None:
    node.validate()
    checked_node_id(node.id, context="node_id")
    checked_ssh_user(ssh_user)
    if not valid_node_address(node.address):
        raise ValueError("invalid node address")
    directory = known_hosts_root / node.id
    known_hosts = directory / "known_hosts"
    if (
        not known_hosts_root.is_absolute()
        or known_hosts_root.is_symlink()
        or directory.is_symlink()
        or known_hosts.is_symlink()
        or not known_hosts.is_file()
    ):
        raise RuntimeError("node SSH host key must be pinned before cookie import")
    cookies = load_cookie_file(source_path)
    payload = json.dumps({"node_id": node.id, "cookies": cookies}, ensure_ascii=False)
    if len(payload.encode("utf-8")) > MAX_NODE_COOKIE_BYTES:
        raise ValueError("cookie request exceeds the supported size")
    target = ssh_target(ssh_user, node.address)
    # No pseudo-TTY: a remote terminal can echo stdin containing the cookies.
    try:
        result = host.run(
            [
                "ssh",
                "-T",
                *ssh_connection_flags(node.ssh_port, known_hosts),
                *(["-i", str(identity_file), "-o", "IdentitiesOnly=yes"] if identity_file else []),
                target,
                remote_command(
                    ssh_user,
                    "cd /opt/hydra && exec /opt/hydra/.venv/bin/python -m hydra.entrypoints.node_cookies",
                ),
            ],
            input=payload,
            text=True,
            capture_output=True,
            timeout=180,
        )
    except Exception:
        # Timeout/process errors can retain captured remote output containing secrets.
        raise RuntimeError("node VK cookie import failed") from None
    if result.returncode != 0:
        raise RuntimeError("node VK cookie import failed")
