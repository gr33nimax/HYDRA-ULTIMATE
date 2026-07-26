"""Traffic-accounting and journal runtime for Telemt."""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from .mtproto_stats_model import (
    CHAIN_IN,
    CHAIN_OUT,
    SERVICE_NAME,
    now_string,
    today,
)

Run = Callable[..., object]


def chain_exists(chain: str, run: Run) -> bool:
    return run(["iptables", "-L", chain, "-n"], capture=True).returncode == 0


def setup_accounting(
    port: int,
    *,
    run: Run,
    cron_file: Path,
) -> None:
    for chain in (CHAIN_IN, CHAIN_OUT):
        if not chain_exists(chain, run):
            run(["iptables", "-N", chain])
    rules = (
        ("INPUT", "--dport", CHAIN_IN, "telemt-rx"),
        ("OUTPUT", "--sport", CHAIN_OUT, "telemt-tx"),
    )
    for parent, port_flag, chain, comment in rules:
        base = ["-p", "tcp", port_flag, str(port), "-j", chain]
        run(["iptables", "-D", parent, *base])
        run(["iptables", "-I", parent, "1", *base])
        run(["iptables", "-F", chain])
        run(
            [
                "iptables", "-A", chain, "-p", "tcp", port_flag, str(port),
                "-m", "comment", "--comment", comment, "-j", "RETURN",
            ]
        )
    try:
        cron_file.write_text(
            f"0 0 * * * root iptables -Z {CHAIN_IN} && "
            f"iptables -Z {CHAIN_OUT}  # telemt-stats\n"
        )
        cron_file.chmod(0o644)
    except Exception:
        pass


def read_chain_bytes(chain: str, run: Run) -> int:
    result = run(
        ["iptables", "-L", chain, "-v", "-n", "-x"],
        capture=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[1])
    return 0


def reset_accounting(run: Run) -> None:
    for chain in (CHAIN_IN, CHAIN_OUT):
        run(["iptables", "-Z", chain])


def parse_journal(
    run: Run,
    since: str | None = None,
) -> dict:
    command = [
        "journalctl",
        "-u",
        SERVICE_NAME,
        "--no-pager",
        "-o",
        "short-iso",
    ]
    if since:
        command += ["--since", since]
    result: dict = {}
    for line in run(command, capture=True).stdout.splitlines():
        match = re.search(
            r"(?:user[=:\[]\s*|client[=:\[]\s*)"
            r"([a-zA-Z][a-zA-Z0-9_\-]+)",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        username = match.group(1)
        if username.lower() in ("root", "telemt", "system", "service"):
            continue
        user = result.setdefault(
            username,
            {"sessions": 0, "last_seen": "—"},
        )
        timestamp = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
            line,
        )
        if timestamp:
            user["last_seen"] = timestamp.group(1).replace("T", " ")
        if re.search(r"connect|new.?client|auth.?ok", line, re.IGNORECASE):
            user["sessions"] += 1
    return result


def collect(
    data: dict,
    *,
    read_bytes: Callable[[str], int],
    journal: Callable[..., dict],
    configured_users: Callable[[], dict],
) -> dict:
    day = today()
    try:
        received = read_bytes(CHAIN_IN)
        transmitted = read_bytes(CHAIN_OUT)
        data["ipt_ok"] = True
    except Exception:
        received = transmitted = 0
        data["ipt_ok"] = False
    daily = data.setdefault("daily", {})
    daily.setdefault(day, {"rx": 0, "tx": 0})
    if data["ipt_ok"]:
        daily[day] = {"rx": received, "tx": transmitted}
        data["total"]["rx"] = sum(item["rx"] for item in daily.values())
        data["total"]["tx"] = sum(item["tx"] for item in daily.values())
    sessions = journal(data["total"].get("since") or None)
    users = data.setdefault("users", {})
    for username, observation in sessions.items():
        current = users.setdefault(
            username,
            {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"},
        )
        current["sessions"] = max(
            current["sessions"],
            observation["sessions"],
        )
        if observation["last_seen"] != "—":
            current["last_seen"] = observation["last_seen"]
    for username in configured_users():
        users.setdefault(
            username,
            {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "—"},
        )
    _allocate_user_bytes(data)
    data["total"]["updated"] = now_string()
    return data


def _allocate_user_bytes(data: dict) -> None:
    if not data["ipt_ok"]:
        return
    total_rx = data["total"].get("rx", 0)
    total_tx = data["total"].get("tx", 0)
    if total_rx <= 0 and total_tx <= 0:
        return
    users = data["users"]
    names = list(users)
    sessions = sum(users[name]["sessions"] for name in names)
    if sessions:
        for name in names:
            ratio = users[name]["sessions"] / sessions
            users[name]["rx"] = int(total_rx * ratio)
            users[name]["tx"] = int(total_tx * ratio)
        return
    active = [name for name in names if users[name]["last_seen"] != "—"] or names
    count = max(len(active), 1)
    for index, name in enumerate(active):
        users[name]["rx"] = total_rx // count
        users[name]["tx"] = total_tx // count
        if index == count - 1:
            users[name]["rx"] += total_rx % count
            users[name]["tx"] += total_tx % count
