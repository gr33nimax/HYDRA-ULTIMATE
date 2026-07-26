"""Compatibility facade for the split Telemt fallback implementation.

Dependencies are resolved here at call time to retain legacy import and
``monkeypatch`` seams while implementation modules stay one-way.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Thread
from typing import Callable, Optional

from hydra.core.host import HOST
from hydra.plugins.telemt import (
    telemt_fallback_console as _console,
    telemt_fallback_model as _model,
    telemt_fallback_orchestrator as _orchestrator,
    telemt_fallback_probe as _probe,
    telemt_fallback_runtime as _runtime,
)

_SERVICE_NAME = "telemt"
_CONFIG_FILE = Path("/etc/telemt/telemt.toml")
_LOG_FILE = Path("/var/log/telemt_install.log")
_ME_ENDPOINTS = _probe.ME_ENDPOINTS
_PROXY_CONFIG_URL = _probe.PROXY_CONFIG_URL
_PROXY_CONFIG_TIMEOUT = _probe.PROXY_CONFIG_TIMEOUT
_ME_QUORUM = _probe.ME_QUORUM
_PROBE_TCP_TIMEOUT = _probe.PROBE_TCP_TIMEOUT
_ME_FAILURE_PATTERNS = list(_probe.ME_FAILURE_PATTERNS)


def _colors() -> dict[str, str]:
    if sys.stdout.isatty():
        return {
            "RED": "\033[0;31m",
            "GREEN": "\033[0;32m",
            "YELLOW": "\033[1;33m",
            "CYAN": "\033[0;36m",
            "BOLD": "\033[1m",
            "DIM": "\033[2m",
            "WHITE": "\033[1;37m",
            "NC": "\033[0m",
        }
    return {
        key: ""
        for key in (
            "RED",
            "GREEN",
            "YELLOW",
            "CYAN",
            "BOLD",
            "DIM",
            "WHITE",
            "NC",
        )
    }


_C = _colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C["RED"],
    _C["GREEN"],
    _C["YELLOW"],
    _C["CYAN"],
    _C["BOLD"],
    _C["DIM"],
    _C["WHITE"],
    _C["NC"],
)

FallbackConfig = _model.FallbackConfig


class MiddleProxyProbe(_probe.MiddleProxyProbe):
    """Compatibility probe wired to the facade's ``Thread`` seam."""

    def __init__(
        self,
        endpoints: list[tuple[str, int]] = _ME_ENDPOINTS,
        tcp_timeout: float = _PROBE_TCP_TIMEOUT,
        quorum: float = _ME_QUORUM,
    ) -> None:
        super().__init__(
            endpoints,
            tcp_timeout,
            quorum,
            thread_factory=lambda **kwargs: Thread(**kwargs),
        )


def fetch_live_me_endpoints(
    url: str = _PROXY_CONFIG_URL,
    timeout: float = _PROXY_CONFIG_TIMEOUT,
) -> list[tuple[str, int]]:
    return _probe.fetch_live_me_endpoints(
        url,
        timeout,
        request_factory=urllib.request.Request,
        open_url=urllib.request.urlopen,
    )


def _diagnostic_probe(
    tcp_timeout: float = _PROBE_TCP_TIMEOUT,
    quorum: float = _ME_QUORUM,
) -> MiddleProxyProbe:
    live = fetch_live_me_endpoints()
    return MiddleProxyProbe(live or _ME_ENDPOINTS, tcp_timeout, quorum)


def diagnostic_probe() -> MiddleProxyProbe:
    return _diagnostic_probe()


def middle_proxy_quorum() -> float:
    return _ME_QUORUM


def read_fallback_config(
    config_file: Path = _CONFIG_FILE,
) -> FallbackConfig:
    return _model.read_fallback_config(config_file)


def read_runtime_middle_proxy(
    config_file: Path = _CONFIG_FILE,
) -> Optional[bool]:
    return _model.read_runtime_middle_proxy(config_file)


def append_fallback_section(
    config_file: Path,
    fb: FallbackConfig,
) -> None:
    _model.append_fallback_section(config_file, fb)


def check_journal_for_me_failures(
    lines: int = 100,
    service: str = _SERVICE_NAME,
) -> list[str]:
    return _probe.journal_failure_lines(
        HOST.run,
        lines=lines,
        service=service,
        patterns=_ME_FAILURE_PATTERNS,
    )


def _log_fb(msg: str, level: str = "INFO") -> None:
    _runtime.log_fallback(
        msg,
        level,
        log_file=_LOG_FILE,
        palette=_C,
    )


def _patch_config_middle_proxy(
    config_file: Path,
    enable: bool,
) -> bool:
    return _runtime.patch_config_middle_proxy(
        config_file,
        enable=enable,
        log=lambda message, level: _log_fb(message, level),
    )


def set_runtime_middle_proxy(
    config_file: Path,
    *,
    enable: bool,
) -> bool:
    return _patch_config_middle_proxy(config_file, enable)


def _reload_telemt(service: str = _SERVICE_NAME) -> bool:
    return _runtime.service_operation(
        HOST.run,
        "reload",
        service,
        timeout=15,
    )


def _restart_telemt(service: str = _SERVICE_NAME) -> bool:
    return _runtime.service_operation(
        HOST.run,
        "restart",
        service,
        timeout=30,
    )


def apply_telemt_reload(
    service: str = _SERVICE_NAME,
) -> tuple[bool, str]:
    return _runtime.apply_reload(
        service,
        reload_service=lambda name: _reload_telemt(name),
        restart_service=lambda name: _restart_telemt(name),
        log=lambda message, level: _log_fb(message, level),
    )


def _operations() -> _orchestrator.FallbackOperations:
    return _orchestrator.FallbackOperations(
        journal_failures=lambda: check_journal_for_me_failures(),
        patch_mode=lambda path, enable: _patch_config_middle_proxy(path, enable),
        reload_service=lambda service: _reload_telemt(service),
        read_runtime_mode=lambda path: read_runtime_middle_proxy(path),
        log=lambda message, level: _log_fb(message, level),
        quorum=lambda: _ME_QUORUM,
    )


class FallbackOrchestrator(_orchestrator.FallbackOrchestrator):
    """Compatibility constructor wired to facade-level patch seams."""

    def __init__(
        self,
        fb_config: FallbackConfig,
        config_file: Path = _CONFIG_FILE,
        service: str = _SERVICE_NAME,
        probe: Optional[MiddleProxyProbe] = None,
        on_fallback: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(
            fb_config=fb_config,
            config_file=config_file,
            service=service,
            probe=probe or MiddleProxyProbe(),
            operations=_operations(),
            on_fallback=on_fallback,
            event_factory=lambda: Event(),
            thread_factory=lambda **kwargs: Thread(**kwargs),
        )


def run_post_install_fallback_check(
    config_file: Path = _CONFIG_FILE,
    service: str = _SERVICE_NAME,
    warmup_wait: int = 10,
) -> Optional[str]:
    return _orchestrator.run_post_install_check(
        config_file,
        service,
        warmup_wait,
        read_config=lambda path: read_fallback_config(path),
        read_runtime_mode=lambda path: read_runtime_middle_proxy(path),
        orchestrator_factory=FallbackOrchestrator,
        sleep=time.sleep,
        log=lambda message, level: _log_fb(message, level),
    )


def _palette() -> _console.ConsolePalette:
    return _console.ConsolePalette(
        red=RED,
        green=GREEN,
        yellow=YELLOW,
        cyan=CYAN,
        bold=BOLD,
        dim=DIM,
        white=WHITE,
        reset=NC,
    )


def me_probe_menu(
    config_file: Path = _CONFIG_FILE,
) -> FallbackConfig:
    return _console.me_probe_menu(
        config_file,
        dependencies=_console.ConsoleDependencies(
            read_config=lambda path: read_fallback_config(path),
            fetch_endpoints=lambda: fetch_live_me_endpoints(),
            probe_factory=lambda endpoints: MiddleProxyProbe(endpoints),
            endpoints=_ME_ENDPOINTS,
            quorum=lambda: _ME_QUORUM,
        ),
        palette=_palette(),
    )


def fallback_status_line(
    config_file: Path = _CONFIG_FILE,
) -> str:
    return _console.fallback_status_line(
        read_fallback_config(config_file),
        read_runtime_middle_proxy(config_file),
        _palette(),
    )


def _run_unit_tests() -> None:
    from hydra.plugins.telemt.telemt_fallback_selftest import run

    run(sys.modules[__name__])


if __name__ == "__main__":
    if "--test" in sys.argv:
        _run_unit_tests()
    elif "--probe" in sys.argv:
        print(_diagnostic_probe().summary())
    elif "--status" in sys.argv:
        print(fallback_status_line())
    else:
        print("Usage: python telemt_fallback.py [--test|--probe|--status]")
