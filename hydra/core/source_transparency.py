"""Transparent source preservation for local Caddy L4 backends.

Caddy accepts a public connection and opens a second connection to a loopback
backend.  Binding that connection to the public client's address lets the
backend (and Fail2ban) see the real peer.  Linux must route backend replies back
to that non-local socket; this module owns the narrowly-scoped nftables and
policy-routing state required for that path.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


NFT_TABLE = "hydra-caddy-source"
FWMARK = "0x4859"
ROUTE_TABLE = "51822"
RULE_PRIORITY = "10282"
SYSCTL_KEY = "net.ipv4.ip_nonlocal_bind"
SYSCTL_FILE = Path("/etc/sysctl.d/99-hydra-caddy-source.conf")
STATE_FILE = Path("/var/lib/hydra/caddy-source-state.json")


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, **kwargs)


def _run_checked(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = _run(command, **kwargs)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        stdout = result.stdout.decode(errors="replace") if isinstance(result.stdout, bytes) else result.stdout
        raise RuntimeError(f"{' '.join(command)}: {stderr or stdout or 'unknown error'}")
    return result


def _current_sysctl() -> str:
    result = _run(["sysctl", "-n", SYSCTL_KEY], text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or f"cannot read {SYSCTL_KEY}")
    return result.stdout.strip()


def _save_baseline() -> None:
    if STATE_FILE.exists():
        return
    previous_file = None
    if SYSCTL_FILE.exists():
        previous_file = SYSCTL_FILE.read_text(encoding="utf-8")
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({
        "sysctl": _current_sysctl(),
        "sysctl_file": previous_file,
    }), encoding="utf-8")


def _ruleset(tcp_ports: set[int], udp_ports: set[int], table_exists: bool) -> str:
    lines = []
    if table_exists:
        lines.append(f"delete table inet {NFT_TABLE}")
    lines.extend([
        f"table inet {NFT_TABLE} {{",
        "    chain output {",
        "        type route hook output priority mangle; policy accept;",
    ])
    if tcp_ports:
        ports = ", ".join(str(port) for port in sorted(tcp_ports))
        lines.append(
            f"        ip saddr 127.0.0.0/8 ip daddr != 127.0.0.0/8 "
            f"meta l4proto tcp th sport {{ {ports} }} meta mark set {FWMARK}"
        )
    if udp_ports:
        ports = ", ".join(str(port) for port in sorted(udp_ports))
        lines.append(
            f"        ip saddr 127.0.0.0/8 ip daddr != 127.0.0.0/8 "
            f"meta l4proto udp th sport {{ {ports} }} meta mark set {FWMARK}"
        )
    lines.extend(["    }", "}"])
    return "\n".join(lines) + "\n"


def _validate_ports(ports: set[int]) -> set[int]:
    normalized = {int(port) for port in ports}
    if any(port < 1 or port > 65535 for port in normalized):
        raise ValueError("backend port is outside 1..65535")
    return normalized


def _ensure_policy_rule() -> None:
    rules = _run(["ip", "-4", "rule", "show"], text=True)
    if rules.returncode != 0:
        raise RuntimeError(rules.stderr or "cannot inspect IPv4 policy rules")
    marker = f"fwmark {FWMARK}"
    own_rule = any(
        marker in line and f"lookup {ROUTE_TABLE}" in line
        for line in rules.stdout.splitlines()
    )
    if marker in rules.stdout and not own_rule:
        raise RuntimeError(f"policy-routing mark {FWMARK} is already in use")

    routes = _run(["ip", "-4", "route", "show", "table", ROUTE_TABLE], text=True)
    if routes.returncode != 0:
        detail = str(routes.stderr or routes.stdout or "")
        # Some iproute2 versions return exit code 2 instead of an empty result
        # when a numeric table has never been created. `ip route replace` below
        # creates it, so this is not a collision or configuration failure.
        if "FIB table does not exist" in detail or "ipv4: FIB table does not exist" in detail:
            routes = subprocess.CompletedProcess(
                routes.args, 0, stdout="", stderr="",
            )
        else:
            raise RuntimeError(detail or f"cannot inspect route table {ROUTE_TABLE}")
    expected_route = "local 0.0.0.0/0 dev lo"
    if routes.stdout.strip() and expected_route not in routes.stdout:
        raise RuntimeError(f"policy-routing table {ROUTE_TABLE} is already in use")

    added_rule = False
    try:
        if not own_rule:
            _run_checked([
                "ip", "-4", "rule", "add", "priority", RULE_PRIORITY,
                "fwmark", FWMARK, "lookup", ROUTE_TABLE,
            ])
            added_rule = True
        _run_checked([
            "ip", "-4", "route", "replace", "local", "0.0.0.0/0",
            "dev", "lo", "table", ROUTE_TABLE,
        ])
    except Exception:
        if added_rule:
            _run([
                "ip", "-4", "rule", "del", "priority", RULE_PRIORITY,
                "fwmark", FWMARK, "lookup", ROUTE_TABLE,
            ])
        if not routes.stdout.strip():
            _run(["ip", "-4", "route", "flush", "table", ROUTE_TABLE])
        raise


def apply(tcp_ports: set[int], udp_ports: set[int] | None = None) -> None:
    """Apply source-preserving reply routing for the specified loopback ports."""
    tcp_ports = _validate_ports(tcp_ports)
    udp_ports = _validate_ports(udp_ports or set())
    if not tcp_ports and not udp_ports:
        clear()
        return

    # Detect mark/table collisions before saving or modifying any host state.
    _ensure_policy_rule()
    try:
        _save_baseline()
        SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
        SYSCTL_FILE.write_text(f"{SYSCTL_KEY}=1\n", encoding="utf-8")
        _run_checked(["sysctl", "-w", f"{SYSCTL_KEY}=1"])
        table_exists = _run(
            ["nft", "list", "table", "inet", NFT_TABLE],
        ).returncode == 0
        ruleset = _ruleset(tcp_ports, udp_ports, table_exists)
        _run_checked(["nft", "--check", "-f", "-"], input=ruleset.encode())
        _run_checked(["nft", "-f", "-"], input=ruleset.encode())
    except Exception:
        clear()
        raise


def clear() -> None:
    """Remove owned routing state and restore the pre-Hydra sysctl value."""
    nft_owned = _run(["nft", "list", "table", "inet", NFT_TABLE]).returncode == 0
    rules = _run(["ip", "-4", "rule", "show"], text=True)
    rule_owned = rules.returncode == 0 and any(
        f"fwmark {FWMARK}" in line and f"lookup {ROUTE_TABLE}" in line
        for line in rules.stdout.splitlines()
    )
    if not (STATE_FILE.exists() or nft_owned or rule_owned):
        return
    _run(["nft", "delete", "table", "inet", NFT_TABLE])
    _run([
        "ip", "-4", "rule", "del", "priority", RULE_PRIORITY,
        "fwmark", FWMARK, "lookup", ROUTE_TABLE,
    ])
    _run(["ip", "-4", "route", "flush", "table", ROUTE_TABLE])

    if not STATE_FILE.exists():
        return
    try:
        baseline = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        previous_file = baseline.get("sysctl_file")
        if previous_file is None:
            SYSCTL_FILE.unlink(missing_ok=True)
        else:
            SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
            SYSCTL_FILE.write_text(str(previous_file), encoding="utf-8")
        previous_value = str(baseline.get("sysctl", "0"))
        _run(["sysctl", "-w", f"{SYSCTL_KEY}={previous_value}"])
    finally:
        STATE_FILE.unlink(missing_ok=True)


def _parse_ports(value: str) -> set[int]:
    if not value:
        return set()
    return _validate_ports({int(item) for item in value.split(",") if item})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "clear"))
    parser.add_argument("--tcp", default="")
    parser.add_argument("--udp", default="")
    args = parser.parse_args()
    if args.action == "apply":
        apply(_parse_ports(args.tcp), _parse_ports(args.udp))
    else:
        clear()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
