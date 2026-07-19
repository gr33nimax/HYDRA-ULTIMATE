"""hydra/core/nft.py — nftables TPROXY: заворот трафика транспортов в sing-box."""
from __future__ import annotations

from subprocess import CompletedProcess
from dataclasses import dataclass
from typing import TYPE_CHECKING
from hydra.utils.commands import DEFAULT_TIMEOUT
from hydra.core.host import HOST

if TYPE_CHECKING:
    from hydra.plugins.base import ConfigFragment

NFT_TABLE = "hydra-tproxy"


@dataclass(frozen=True)
class TproxySnapshot:
    ruleset: str | None
    policy_routing: bool


def snapshot_tproxy() -> TproxySnapshot:
    """Capture only HYDRA's nft table and policy-routing presence."""
    if not HOST.which("nft"):
        return TproxySnapshot(None, False)
    table = HOST.run(
        ["nft", "list", "table", "inet", NFT_TABLE],
        text=True,
    )
    ruleset = table.stdout if table.returncode == 0 else None
    policy = False
    if HOST.which("ip"):
        rule = HOST.run(
            ["ip", "rule", "show", "fwmark", "0x1"],
            text=True,
        )
        policy = rule.returncode == 0 and "0x1" in rule.stdout
    return TproxySnapshot(ruleset, policy)


def restore_tproxy(snapshot: TproxySnapshot) -> None:
    """Restore a HYDRA-only snapshot without touching unrelated firewall rules."""
    if not HOST.which("nft"):
        return
    HOST.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
    )
    if snapshot.ruleset:
        _run_checked(["nft", "-f", "-"], input=snapshot.ruleset.encode())
    if snapshot.policy_routing:
        _ensure_policy_routing()
    else:
        _cleanup_policy_routing()


def _run_checked(cmd: list[str], **kwargs) -> CompletedProcess:
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    result = HOST.run(cmd, **kwargs)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        raise RuntimeError(f"{' '.join(cmd)} failed: {stderr or 'unknown error'}")
    return result


def _ensure_tproxy_modules():
    """Загружает kernel modules, необходимые для nftables TPROXY."""
    for mod in ("nft_tproxy", "nf_tproxy_ipv4", "nf_tproxy_ipv6"):
        _run_checked(
            ["modprobe", mod],
        )


def _ensure_policy_routing():
    """Настраивает ip rule + ip route для TPROXY (fwmark 0x1 → local routing)."""
    r = HOST.run(
        ["ip", "rule", "show", "fwmark", "0x1"],
        text=True,
    )
    if "0x1" not in r.stdout:
        _run_checked(["ip", "rule", "add", "fwmark", "0x1", "table", "100"])

    r = HOST.run(
        ["ip", "route", "show", "table", "100"],
        text=True,
    )
    if "local" not in r.stdout:
        _run_checked(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])


def _cleanup_policy_routing():
    """Удаляет policy routing правила TPROXY."""
    HOST.run(["ip", "rule", "del", "fwmark", "0x1", "table", "100"])
    HOST.run(["ip", "route", "flush", "table", "100"])


def apply_tproxy(fragments: dict, tproxy_port: int = 1081) -> None:
    _ensure_tproxy_modules()

    ports: set[int] = set()
    ifaces: set[str] = set()
    for frag in fragments.values():
        ports.update(getattr(frag, "nft_tproxy_ports", []))
        ifaces.update(getattr(frag, "nft_tproxy_ifaces", []))

    if not ports and not ifaces:
        HOST.run(["nft", "delete", "table", "inet", NFT_TABLE])
        _cleanup_policy_routing()
        return

    table_exists = HOST.run(["nft", "list", "table", "inet", NFT_TABLE]).returncode == 0
    ruleset = f"delete table inet {NFT_TABLE}\n" if table_exists else ""
    ruleset += f"table inet {NFT_TABLE} {{\n"
    ruleset += "    chain prerouting {\n"
    ruleset += "        type filter hook prerouting priority mangle; policy accept;\n"
    ruleset += "        meta mark 0xff return\n"
    ruleset += "        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } return\n"

    if ports:
        port_list = ", ".join(str(p) for p in sorted(ports))
        ruleset += (
            f"        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} "
            f"meta mark set 0x1 tproxy ip to 127.0.0.1:{tproxy_port} accept\n"
        )

    for iface in sorted(ifaces):
        ruleset += (
            f'        iifname "{iface}" meta l4proto {{ tcp, udp }} '
            f"meta mark set 0x1 tproxy ip to 127.0.0.1:{tproxy_port} accept\n"
        )

    ruleset += "    }\n"

    if ports:
        port_list = ", ".join(str(p) for p in sorted(ports))
        ruleset += "    chain output {\n"
        ruleset += "        type route hook output priority mangle; policy accept;\n"
        ruleset += "        meta mark 0xff return\n"
        ruleset += f"        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} meta mark set 0x1\n"
        ruleset += "    }\n"

    ruleset += "}\n"

    _run_checked(["nft", "--check", "-f", "-"], input=ruleset.encode())
    _run_checked(["nft", "-f", "-"], input=ruleset.encode())

    _ensure_policy_routing()


def clear_tproxy() -> None:
    HOST.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
    )
    _cleanup_policy_routing()


def persist() -> None:
    try:
        result = HOST.run(
            ["nft", "list", "ruleset"],
            text=True,
        )
        if result.returncode == 0:
            HOST.atomic_write(HOST.paths.nftables_rules, result.stdout, mode=0o600)
    except Exception:
        pass
