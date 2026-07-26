"""Telemt config mutation, service activation, and fallback logging."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


DC_OVERRIDES = (
    '"1"   = "149.154.175.50:443"\n'
    '"2"   = "149.154.167.51:443"\n'
    '"3"   = "149.154.175.100:443"\n'
    '"4"   = "149.154.167.91:443"\n'
    '"5"   = "91.108.4.100:443"\n'
    '"203" = "91.105.192.100:443"\n'
)


def render_middle_proxy_mode(text: str, *, enable: bool) -> str:
    """Render a single, internally consistent runtime mode in Telemt TOML."""

    key_pattern = r"^use_middle_proxy\s*=\s*(true|false)"
    if re.search(key_pattern, text, flags=re.MULTILINE | re.IGNORECASE):
        rendered = re.sub(
            r"^(use_middle_proxy\s*=\s*)(true|false)",
            f"use_middle_proxy = {str(enable).lower()}",
            text,
            count=1,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        output: list[str] = []
        seen = False
        for line in rendered.splitlines():
            if re.match(r"^use_middle_proxy\s*=", line, re.IGNORECASE):
                if seen:
                    continue
                seen = True
            output.append(line)
        rendered = "\n".join(output)
        if not rendered.endswith("\n"):
            rendered += "\n"
    else:
        rendered = re.sub(
            r"(\[general\])",
            f"\\1\nuse_middle_proxy = {str(enable).lower()}",
            text,
            count=1,
        )

    if not enable:
        if "[dc_overrides]" not in rendered:
            rendered = rendered.rstrip() + "\n\n[dc_overrides]\n" + DC_OVERRIDES
        return rendered

    output = []
    skipping = False
    for line in rendered.splitlines():
        if line.strip() == "[dc_overrides]":
            skipping = True
            continue
        if skipping and line.strip().startswith("["):
            skipping = False
        if not skipping:
            output.append(line)
    return "\n".join(output).rstrip() + "\n"


def patch_config_middle_proxy(
    config_file: Path,
    *,
    enable: bool,
    log: Callable[[str, str], None],
) -> bool:
    """Persist one internally consistent Direct/Middle mode."""

    if not config_file.exists():
        return False
    try:
        text = config_file.read_text(encoding="utf-8", errors="replace")
        config_file.write_text(
            render_middle_proxy_mode(text, enable=enable),
            encoding="utf-8",
        )
        config_file.chmod(0o640)
        return True
    except Exception as exc:
        log(f"Ошибка записи конфига: {exc}", "ERROR")
        return False


def log_fallback(
    message: str,
    level: str,
    *,
    log_file: Path,
    palette: dict[str, str],
) -> None:
    """Write a fallback event to the installer log and current console."""

    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a") as stream:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            stream.write(f"[{timestamp}] [{level}] FALLBACK: {message}\n")
    except Exception:
        pass
    prefix = {
        "INFO": f"  {palette['CYAN']}→{palette['NC']}  ",
        "WARN": f"  {palette['YELLOW']}⚠{palette['NC']}  ",
        "ERROR": f"  {palette['RED']}✗{palette['NC']}  ",
        "OK": f"  {palette['GREEN']}✓{palette['NC']}  ",
    }.get(level, "  ")
    print(f"{prefix}{message}", flush=True)


def service_operation(
    runner: Callable[..., Any],
    operation: str,
    service: str,
    *,
    timeout: int,
) -> bool:
    """Run one systemd service operation and normalize errors to ``False``."""

    try:
        result = runner(
            ["systemctl", operation, service],
            capture_output=True,
            timeout=timeout,
        )
        return result.returncode == 0
    except Exception:
        return False


def apply_reload(
    service: str,
    *,
    reload_service: Callable[[str], bool],
    restart_service: Callable[[str], bool],
    log: Callable[[str, str], None],
) -> tuple[bool, str]:
    """Apply a config via reload, falling back to a full restart."""

    if reload_service(service):
        log("Конфиг применён через systemctl reload (SIGHUP).", "OK")
        return True, "reload"
    log(
        "systemctl reload не сработал — пробую полный restart.",
        "WARN",
    )
    if restart_service(service):
        log("Конфиг применён через systemctl restart.", "OK")
        return True, "restart"
    log(
        "Не удалось применить конфиг ни через reload, ни через restart.",
        "ERROR",
    )
    return False, "none"
