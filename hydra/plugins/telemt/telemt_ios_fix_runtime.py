"""Host runtime operations for Telemt's iOS-specific endpoint."""
from __future__ import annotations

import json
import re
import shutil
import socket
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from .telemt_ios_fix_model import IosFixConfig

Run = Callable[..., object]


def get_telemt_port(config_file: Path) -> int:
    if not config_file.exists():
        return 0
    match = re.search(
        r"^port\s*=\s*(\d+)",
        config_file.read_text(),
        re.MULTILINE,
    )
    return int(match.group(1)) if match else 0


def get_current_mss(config_file: Path) -> str:
    if not config_file.exists():
        return ""
    try:
        match = re.search(
            r'^client_mss\s*=\s*"?([^"\s]+)"?',
            config_file.read_text(),
            re.MULTILINE,
        )
        return match.group(1) if match else ""
    except Exception:
        return ""


def strip_client_mss(config_file: Path) -> bool:
    if not config_file.exists():
        return False
    content = config_file.read_text()
    updated = re.sub(
        r'^client_mss\s*=\s*"[^"]*"\n?',
        "",
        content,
        flags=re.MULTILINE,
    )
    if updated == content:
        return False
    config_file.write_text(updated)
    config_file.chmod(0o640)
    return True


def port_in_use(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            candidate.bind(("0.0.0.0", port))
    except OSError:
        return True
    except Exception:
        return False
    return False


def pick_free_port(
    start: int,
    exclude: int,
    *,
    occupied=port_in_use,
) -> int:
    port = max(1, min(start, 65535))
    for _ in range(100):
        if port != exclude and not occupied(port):
            return port
        port = 1024 if port >= 65535 else port + 1
    return 0


def load_state(state_file: Path) -> IosFixConfig:
    if not state_file.exists():
        return IosFixConfig()
    try:
        data = json.loads(state_file.read_text())
        fields = IosFixConfig.__dataclass_fields__
        return IosFixConfig(**{key: data[key] for key in fields if key in data})
    except Exception:
        return IosFixConfig()


def save_state(config: IosFixConfig, state_file: Path) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(
            json.dumps(asdict(config), ensure_ascii=False, indent=2)
        )
    except Exception:
        pass


def rules_exist(run: Run, comment_tag: str) -> bool:
    result = run(
        ["iptables", "-t", "mangle", "-S", "PREROUTING"],
        capture=True,
    )
    return comment_tag in (result.stdout or "")


def remove_rules(run: Run, comment_tag: str) -> int:
    removed = 0
    for table in ("mangle", "nat"):
        for _ in range(20):
            result = run(
                ["iptables", "-t", table, "-S", "PREROUTING"],
                capture=True,
            )
            rules = [
                line
                for line in (result.stdout or "").splitlines()
                if comment_tag in line
            ]
            if not rules or not rules[0].startswith("-A PREROUTING"):
                break
            command = (
                ["iptables", "-t", table, "-D", "PREROUTING"]
                + rules[0].split()[2:]
            )
            if run(command, capture=True).returncode != 0:
                break
            removed += 1
    return removed


def apply_rules(
    config: IosFixConfig,
    *,
    run: Run,
    comment_tag: str,
) -> tuple[bool, str]:
    if config.ext_port <= 0 or config.target_port <= 0:
        return False, "Не заданы порты."
    remove_rules(run, comment_tag)
    mss = [
        "iptables", "-t", "mangle", "-A", "PREROUTING",
        "-p", "tcp", "--dport", str(config.ext_port),
        "--tcp-flags", "SYN,RST", "SYN",
        "-m", "comment", "--comment", comment_tag,
        "-j", "TCPMSS", "--set-mss", str(config.mss),
    ]
    redirect = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", str(config.ext_port),
        "-m", "comment", "--comment", comment_tag,
        "-j", "REDIRECT", "--to-port", str(config.target_port),
    ]
    result = run(mss, capture=True)
    if result.returncode != 0:
        return False, f"Ошибка TCPMSS-правила: {result.stderr.strip()[:120]}"
    result = run(redirect, capture=True)
    if result.returncode != 0:
        remove_rules(run, comment_tag)
        return False, f"Ошибка REDIRECT-правила: {result.stderr.strip()[:120]}"
    return True, "Правила TCPMSS + REDIRECT применены."


def persist_rules(run: Run, rules_path: Path) -> None:
    if shutil.which("netfilter-persistent"):
        run(["netfilter-persistent", "save"])
        return
    if not rules_path.parent.exists():
        return
    try:
        result = run(["iptables-save"], capture=True)
        if result.returncode == 0 and result.stdout:
            rules_path.write_text(result.stdout)
    except Exception:
        pass
