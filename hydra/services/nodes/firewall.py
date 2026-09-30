"""Restrict the node control port to its pinned base-server address."""

from __future__ import annotations

import ipaddress

from hydra.core.host import HostBackend
from hydra.core.node_identity import NodeIdentity

_TABLE = "hydra-node-control"
_NFT_TIMEOUT = 15


def render_control_firewall(identity: NodeIdentity) -> str:
    """Build the isolated nftables table for one node's control listener."""
    identity.validate()
    address = ipaddress.ip_address(identity.base_ip)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    family = "ip6" if isinstance(address, ipaddress.IPv6Address) else "ip"
    return (
        f"table inet {_TABLE} {{\n"
        "  chain input {\n"
        "    type filter hook input priority filter; policy accept;\n"
        f"    {family} saddr {address.compressed} tcp dport {identity.control_port} accept\n"
        f"    tcp dport {identity.control_port} drop\n"
        "  }\n"
        "}\n"
    )


def _run(host: HostBackend, args: list[str], *, input: str | None = None):
    return host.run(args, timeout=_NFT_TIMEOUT, text=True, input=input)


def _restore_previous(host: HostBackend, previous: str, cause: Exception) -> None:
    replacement = f"delete table inet {_TABLE}\n{previous}"
    try:
        restored = _run(host, ["nft", "-f", "-"], input=replacement)
    except Exception as exc:
        raise RuntimeError("could not restore previous node control firewall") from exc
    if restored.returncode != 0:
        raise RuntimeError("could not restore previous node control firewall") from cause


def remove_control_firewall(*, host: HostBackend) -> None:
    """Remove only the dedicated Hydra control table, if it exists."""
    if not host.which("nft"):
        raise RuntimeError("nftables is required for the node control firewall")
    listed = _run(host, ["nft", "list", "tables"])
    if listed.returncode != 0:
        raise RuntimeError("could not inspect nftables tables")
    if f"table inet {_TABLE}" not in (listed.stdout or "").splitlines():
        return
    removed = _run(host, ["nft", "-f", "-"], input=f"delete table inet {_TABLE}\n")
    if removed.returncode != 0:
        raise RuntimeError("could not remove node control firewall")


def apply_control_firewall(identity: NodeIdentity, *, host: HostBackend) -> None:
    """Validate, replace, and roll back the node-owned firewall table."""
    if not host.which("nft"):
        raise RuntimeError("nftables is required for the node control firewall")

    listed = _run(host, ["nft", "list", "tables"])
    if listed.returncode != 0:
        raise RuntimeError("could not inspect nftables tables")
    table_exists = f"table inet {_TABLE}" in listed.stdout.splitlines()
    previous = None
    if table_exists:
        current = _run(host, ["nft", "list", "table", "inet", _TABLE])
        if current.returncode != 0 or not current.stdout:
            raise RuntimeError("could not snapshot previous node control firewall")
        previous = current.stdout

    replacement = f"delete table inet {_TABLE}\n" if table_exists else ""
    ruleset = replacement + render_control_firewall(identity)
    checked = _run(host, ["nft", "--check", "-f", "-"], input=ruleset)
    if checked.returncode != 0:
        raise RuntimeError("node control firewall rules failed validation")

    try:
        applied = _run(host, ["nft", "-f", "-"], input=ruleset)
        if applied.returncode != 0:
            raise RuntimeError("nftables rejected node control firewall")
    except Exception as exc:
        if previous is not None:
            _restore_previous(host, previous, exc)
        raise RuntimeError("could not apply node control firewall") from exc


__all__ = ["apply_control_firewall", "remove_control_firewall", "render_control_firewall"]
