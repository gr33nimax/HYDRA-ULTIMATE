"""Console adapter and compatibility surface for Telemt SYN limiting."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from typing import Optional

from hydra.core.host import HOST

from . import telemt_syn_limiter_runtime as _runtime
from .telemt_syn_limiter_model import (
    COMMENT_TAG as _COMMENT_TAG,
    CONFIG_FILE as _CONFIG_FILE,
    HASHLIMIT_NAME as _HASHLIMIT_NAME,
    PRESETS as _PRESETS,
    STATE_FILE as _STATE_FILE,
    SynLimiterConfig,
)

_colors = {
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "CYAN": "\033[36m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "NC": "\033[0m",
} if sys.stdout.isatty() else {key: "" for key in (
    "RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "DIM", "NC"
)}
_C = _colors
RED = _colors["RED"]
GREEN = _colors["GREEN"]
YELLOW = _colors["YELLOW"]
CYAN = _colors["CYAN"]
WHITE = _colors["WHITE"]
BOLD = _colors["BOLD"]
DIM = _colors["DIM"]
NC = _colors["NC"]
_SERVICE_NAME = "telemt"
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


def _box_wrap(text: str, indent: str = "  ") -> None:
    width = max(1, _BOX_W - _wlen(indent))
    for start in range(0, len(text), width):
        _box_row(indent + text[start : start + width])


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
    kwargs = {}
    if capture:
        kwargs.update(capture_output=True, text=True)
    return HOST.run(cmd, **kwargs)


def _get_telemt_port() -> int:
    return _runtime.get_telemt_port(_CONFIG_FILE)


def _load_state() -> SynLimiterConfig:
    return _runtime.load_state(_STATE_FILE)


def _save_state(config: SynLimiterConfig) -> None:
    _runtime.save_state(config, _STATE_FILE)


def _rule_exists() -> bool:
    return _runtime.rule_exists(_run, _COMMENT_TAG)


def _remove_rules() -> int:
    return _runtime.remove_rules(_run, _COMMENT_TAG)


def _apply_rules(config: SynLimiterConfig) -> tuple[bool, str]:
    return _runtime.apply_rules(
        config,
        run=_run,
        comment_tag=_COMMENT_TAG,
        hashlimit_name=_HASHLIMIT_NAME,
    )


def _persist_rules() -> None:
    _runtime.persist_rules(_run, Path("/etc/iptables/rules.v4"))


def _get_drop_counter(port: int) -> tuple[int, int]:
    return _runtime.counter(_run, _COMMENT_TAG, "DROP")


def _get_accept_counter(port: int) -> tuple[int, int]:
    return _runtime.counter(_run, _COMMENT_TAG, "ACCEPT")


def status() -> dict:
    config = _load_state()
    active = _rule_exists()
    return {
        "enabled": config.enabled and active,
        "configured_but_inactive": config.enabled and not active,
        "rate": config.rate_per_sec,
        "burst": config.burst,
        "preset": config.preset_name,
        "port": config.port,
    }


def syn_limiter_status_line() -> str:
    current = status()
    if current["enabled"]:
        return (
            f"{GREEN}● активен{NC}  {DIM}{current['rate']}/sec "
            f"burst {current['burst']} (port {current['port']}){NC}"
        )
    if current["configured_but_inactive"]:
        return f"{YELLOW}⚠ включён в конфиге, но правил нет в iptables{NC}"
    return f"{DIM}не активен{NC}"


def _show_preset_picker() -> Optional[tuple]:
    print("\n  Защита от SYN-штормов")
    for key, (name, rate, burst, label, detail, recommended) in _PRESETS.items():
        marker = " (рекомендуется)" if recommended else ""
        print(f"  [{key}] {label}: {detail}{marker}")
    print("  [C] Свой rate/burst\n  [Q] Отмена")
    while True:
        raw = _ask("  Выбор [1-3/C/Q] (Enter=1): ", "1").lower()
        if raw == "q":
            return None
        if raw == "c":
            try:
                rate = int(_ask("  Rate (1-50): "))
                burst = int(_ask("  Burst (1-20): "))
                if 1 <= rate <= 50 and 1 <= burst <= 20:
                    return "custom", rate, burst, "Свой"
            except (ValueError, _Cancelled):
                pass
            print("  Нужны целые значения в допустимом диапазоне.")
            continue
        if raw in _PRESETS:
            name, rate, burst, label, _, _ = _PRESETS[raw]
            return name, rate, burst, label


def _show_live_counter(config: SynLimiterConfig) -> None:
    try:
        while True:
            accepted, _ = _get_accept_counter(config.port)
            dropped, _ = _get_drop_counter(config.port)
            total = accepted + dropped
            ratio = dropped / total * 100 if total else 0
            print(
                f"\r  SYN accepted={accepted:,}, dropped={dropped:,} "
                f"({ratio:.1f}%)   Ctrl+C — выход",
                end="",
                flush=True,
            )
            time.sleep(2)
    except KeyboardInterrupt:
        print()


def _enable_from_picker() -> None:
    picked = _show_preset_picker()
    if picked is None:
        return
    name, rate, burst, label = picked
    port = _get_telemt_port()
    if port <= 0:
        print("  Не удалось определить порт Telemt.")
        _pause()
        return
    config = SynLimiterConfig(
        enabled=True,
        port=port,
        rate_per_sec=rate,
        burst=burst,
        preset_name=name,
    )
    ok, message = _apply_rules(config)
    if ok:
        _persist_rules()
        _save_state(config)
        print(f"  Лимитер включён: {label} на порту {port}.")
    else:
        print(f"  {message}")
    _pause()


def syn_limiter_menu() -> None:
    while True:
        config = _load_state()
        active = _rule_exists()
        print("\n  SYN-LIMITER")
        print(f"  Статус: {syn_limiter_status_line()}")
        print("  [1] Включить/изменить пресет")
        print("  [2] Живой счётчик")
        print("  [3] Выключить и удалить правила")
        print("  [Q] Назад")
        try:
            choice = _ask("  Выбор: ").lower()
        except _Cancelled:
            return
        if choice == "1":
            _enable_from_picker()
        elif choice == "2":
            if active:
                _show_live_counter(config)
            else:
                print("  Лимитер не активен.")
                _pause()
        elif choice == "3":
            disable_syn_limiter()
            print("  Лимитер выключен.")
            _pause()
        elif choice in ("q", ""):
            return


def disable_syn_limiter() -> None:
    _remove_rules()
    _persist_rules()
    _save_state(SynLimiterConfig(enabled=False))


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Запустите от root.")
        raise SystemExit(1)
    syn_limiter_menu()
