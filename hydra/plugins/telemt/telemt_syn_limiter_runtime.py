"""Host runtime operations for the Telemt SYN limiter."""
from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from .telemt_syn_limiter_model import SynLimiterConfig

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


def load_state(state_file: Path) -> SynLimiterConfig:
    if not state_file.exists():
        return SynLimiterConfig()
    try:
        data = json.loads(state_file.read_text())
        fields = SynLimiterConfig.__dataclass_fields__
        return SynLimiterConfig(**{k: data[k] for k in fields if k in data})
    except Exception:
        return SynLimiterConfig()


def save_state(config: SynLimiterConfig, state_file: Path) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(
            json.dumps(asdict(config), ensure_ascii=False, indent=2)
        )
    except Exception:
        pass


def rule_exists(run: Run, comment_tag: str) -> bool:
    result = run(["iptables", "-S", "INPUT"], capture=True)
    return comment_tag in (result.stdout or "")


def remove_rules(run: Run, comment_tag: str) -> int:
    removed = 0
    for _ in range(20):
        result = run(["iptables", "-S", "INPUT"], capture=True)
        rules = [
            line
            for line in (result.stdout or "").splitlines()
            if comment_tag in line
        ]
        if not rules or not rules[0].startswith("-A INPUT"):
            break
        delete = ["iptables", "-D", "INPUT"] + rules[0].split()[2:]
        if run(delete, capture=True).returncode != 0:
            break
        removed += 1
    return removed


def apply_rules(
    config: SynLimiterConfig,
    *,
    run: Run,
    comment_tag: str,
    hashlimit_name: str,
) -> tuple[bool, str]:
    if config.port <= 0:
        return False, "Не удалось определить порт Telemt."
    remove_rules(run, comment_tag)
    accept = [
        "iptables",
        "-I",
        "INPUT",
        "1",
        "-p",
        "tcp",
        "--dport",
        str(config.port),
        "--syn",
        "-m",
        "hashlimit",
        "--hashlimit-name",
        hashlimit_name,
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-srcmask",
        "32",
        "--hashlimit-upto",
        f"{config.rate_per_sec}/sec",
        "--hashlimit-burst",
        str(config.burst),
        "--hashlimit-htable-expire",
        str(config.htable_expire_ms),
        "-m",
        "comment",
        "--comment",
        comment_tag,
        "-j",
        "ACCEPT",
    ]
    drop = [
        "iptables",
        "-I",
        "INPUT",
        "2",
        "-p",
        "tcp",
        "--dport",
        str(config.port),
        "--syn",
        "-m",
        "comment",
        "--comment",
        comment_tag,
        "-j",
        "DROP",
    ]
    result = run(accept, capture=True)
    if result.returncode != 0:
        return False, f"Ошибка ACCEPT-правила: {result.stderr.strip()[:120]}"
    result = run(drop, capture=True)
    if result.returncode != 0:
        remove_rules(run, comment_tag)
        return False, f"Ошибка DROP-правила: {result.stderr.strip()[:120]}"
    return True, "Правила hashlimit применены."


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


def counter(run: Run, comment_tag: str, verdict: str) -> tuple[int, int]:
    result = run(
        ["iptables", "-L", "INPUT", "-n", "-v", "-x"],
        capture=True,
    )
    for line in (result.stdout or "").splitlines():
        if comment_tag in line and verdict in line:
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                return int(parts[0]), int(parts[1])
    return 0, 0
