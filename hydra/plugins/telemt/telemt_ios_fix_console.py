"""Console adapter and compatibility surface for Telemt iOS fixing."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

from hydra.core.host import HOST

from . import telemt_ios_fix_runtime as _runtime
from .telemt_ios_fix_model import (
    COMMENT_TAG as _COMMENT_TAG,
    CONFIG_FILE as _CONFIG_FILE,
    SERVICE_NAME as _SERVICE_NAME,
    STATE_FILE as _STATE_FILE,
    IosFixConfig,
)

_colors = {
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "CYAN": "\033[36m",
    "DIM": "\033[2m",
    "NC": "\033[0m",
} if sys.stdout.isatty() else {key: "" for key in (
    "RED", "GREEN", "YELLOW", "CYAN", "DIM", "NC"
)}
_C = _colors
RED = _colors["RED"]
GREEN = _colors["GREEN"]
YELLOW = _colors["YELLOW"]
CYAN = _colors["CYAN"]
DIM = _colors["DIM"]
NC = _colors["NC"]
_BOX_W = 68


def _colors() -> dict:
    return dict(_colors)


def _plain(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _wlen(text: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in _plain(text)
    )


def _box_row(text: str = "") -> None:
    print(f"{CYAN}║{NC}{text}{' ' * max(0, _BOX_W - _wlen(text))}{CYAN}║{NC}")


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        _box_row(title.center(_BOX_W))
        _box_sep()


def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")


def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")


def _box_item(key: str, label: str) -> None:
    _box_row(f"  [{key}]  {label}")


def _box_ok(message: str) -> None:
    _box_row(f"  {GREEN}✓{NC}  {message}")


def _box_warn(message: str) -> None:
    _box_row(f"  {YELLOW}⚠{NC}  {message}")


def _box_info(message: str) -> None:
    _box_row(f"  {CYAN}→{NC}  {message}")


def _box_err(message: str) -> None:
    _box_row(f"  {RED}✗{NC}  {message}")


def _box_kv(key: str, value: str, kw: int = 24) -> None:
    _box_row(f"  {key}{' ' * max(0, kw - _wlen(key))}  {value}")


class _Cancelled(Exception):
    pass


def _pause() -> None:
    try:
        input("\n  Нажмите Enter для продолжения...")
    except (EOFError, KeyboardInterrupt):
        pass


def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    try:
        value = input(prompt).strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise _Cancelled from exc
    return value or default


def _run(
    cmd: list,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    kwargs: dict = {}
    if capture:
        kwargs.update(
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return HOST.run(cmd, **kwargs)
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")


def _get_telemt_port() -> int:
    return _runtime.get_telemt_port(_CONFIG_FILE)


def _get_current_mss() -> str:
    return _runtime.get_current_mss(_CONFIG_FILE)


def _strip_client_mss() -> bool:
    return _runtime.strip_client_mss(_CONFIG_FILE)


def _port_in_use(port: int) -> bool:
    return _runtime.port_in_use(port)


def _pick_free_port(start: int, exclude: int) -> int:
    return _runtime.pick_free_port(start, exclude, occupied=_port_in_use)


def _setup_ufw(port: int) -> None:
    if not shutil.which("ufw"):
        return
    if "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "Telemt iOS-fix"])


def _load_state() -> IosFixConfig:
    return _runtime.load_state(_STATE_FILE)


def _save_state(config: IosFixConfig) -> None:
    _runtime.save_state(config, _STATE_FILE)


def _rules_exist() -> bool:
    return _runtime.rules_exist(_run, _COMMENT_TAG)


def _remove_rules() -> int:
    return _runtime.remove_rules(_run, _COMMENT_TAG)


def _apply_rules(config: IosFixConfig) -> tuple[bool, str]:
    return _runtime.apply_rules(
        config,
        run=_run,
        comment_tag=_COMMENT_TAG,
    )


def _persist_rules() -> None:
    _runtime.persist_rules(_run, Path("/etc/iptables/rules.v4"))


def status() -> dict:
    config = _load_state()
    active = _rules_exist()
    return {
        "enabled": config.enabled and active,
        "configured_but_inactive": config.enabled and not active,
        "ext_port": config.ext_port,
        "target_port": config.target_port,
        "mss": config.mss,
    }


def ios_fix_status_line() -> str:
    current = status()
    if current["enabled"]:
        return (
            f"{GREEN}● активен{NC}  {DIM}порт {current['ext_port']} "
            f"→ {current['target_port']}, MSS {current['mss']}{NC}"
        )
    if current["configured_but_inactive"]:
        return f"{YELLOW}⚠ включён в конфиге, но правил нет в iptables{NC}"
    return f"{DIM}не активен{NC}"


def _read_parameters(target_port: int) -> tuple[int, int] | None:
    default_port = _pick_free_port(target_port + 1, target_port)
    if default_port == 0:
        default_port = target_port + 1 if target_port < 65535 else target_port - 1
    try:
        ext_port = int(_ask(f"  Внешний порт [{default_port}]: ", str(default_port)))
        mss = int(_ask("  MSS (88-4096) [92]: ", "92"))
    except (ValueError, _Cancelled):
        return None
    if (
        not 1 <= ext_port <= 65535
        or ext_port == target_port
        or not 88 <= mss <= 4096
        or _port_in_use(ext_port)
    ):
        return None
    return ext_port, mss


def _enable_fix(target_port: int) -> None:
    parameters = _read_parameters(target_port)
    if parameters is None:
        print("  Некорректные параметры или порт занят.")
        _pause()
        return
    ext_port, mss = parameters
    current_mss = _get_current_mss()
    if current_mss:
        answer = _ask(
            f'  Убрать client_mss="{current_mss}" и продолжить? [Y/n]: ',
            "y",
        ).lower()
        if answer != "y":
            return
        _strip_client_mss()
    config = IosFixConfig(True, ext_port, target_port, mss)
    ok, message = _apply_rules(config)
    if not ok:
        print(f"  {message}")
        _pause()
        return
    _persist_rules()
    _save_state(config)
    _setup_ufw(ext_port)
    _run(["systemctl", "restart", _SERVICE_NAME])
    print(f"  iOS-фикс включён: порт {ext_port} → {target_port}, MSS {mss}.")
    _pause()


def ios_fix_menu() -> None:
    if not _CONFIG_FILE.exists():
        print("  Telemt не установлен.")
        _pause()
        return
    while True:
        target_port = _get_telemt_port()
        print("\n  IOS-ФИКС · MSS + REDIRECT")
        print(f"  Статус: {ios_fix_status_line()}")
        print(f"  Основной порт: {target_port or 'не определён'}")
        print(f"  client_mss: {_get_current_mss() or 'не задан'}")
        print("  [1] Включить/изменить параметры")
        print("  [2] Выключить и удалить правила")
        print("  [Q] Назад")
        try:
            choice = _ask("  Выбор: ").lower()
        except _Cancelled:
            return
        if choice == "1" and target_port > 0:
            _enable_fix(target_port)
        elif choice == "2":
            disable_ios_fix()
            _run(["systemctl", "restart", _SERVICE_NAME])
            print("  iOS-фикс выключен.")
            _pause()
        elif choice in ("q", ""):
            return


def disable_ios_fix() -> None:
    _remove_rules()
    _persist_rules()
    _save_state(IosFixConfig(enabled=False))


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Запустите от root.")
        raise SystemExit(1)
    ios_fix_menu()
