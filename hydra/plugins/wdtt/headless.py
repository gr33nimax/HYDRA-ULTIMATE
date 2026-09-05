"""Deprecated compatibility surface for the former WDTT-owned creator.

Runtime ownership lives in ``ApplicationService.headless_creator``. Legacy
layouts are converted by the one-time state importer.
The WDTT plugin deliberately does not inherit this mixin or advertise these
methods as commands, queries, actions, or maintenance tasks.
"""
from __future__ import annotations

import re

from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt.call_pool import build_qwdtt_link


REFRESH_INTERVAL = 86_400
MIN_REFRESH_INTERVAL = 3_600
MAX_REFRESH_INTERVAL = 86_400
REFRESH_INTERVAL_KEY = "qwdtt_refresh_interval_seconds"
HEADLESS_MAINTENANCE_TASKS: tuple[()] = ()
_MOVED = "VK creator management moved to ApplicationService.headless_creator"


def extract_hash(value: str) -> str:
    match = re.search(r"(?:/join/|join/)([^/?#\s]+)", str(value or ""))
    if match is None:
        raise ValueError("creator returned an invalid VK call link")
    return match.group(1)


def normalize_cookies(*_args, **_kwargs) -> str:
    raise RuntimeError(_MOVED)


def install(*_args, **_kwargs) -> tuple[bool, str]:
    return False, _MOVED


def setup(*_args, **_kwargs) -> tuple[bool, str]:
    return False, _MOVED


def stop(*_args, **_kwargs) -> tuple[bool, str]:
    return False, _MOVED


def uninstall(*_args, **_kwargs) -> None:
    raise RuntimeError(_MOVED)


def due(*_args, **_kwargs) -> bool:
    return False


class WdttHeadlessMixin:
    """Legacy direct-call shim; no longer part of ``WdttPlugin``."""

    def setup_headless_creator(self, **_kwargs) -> tuple[bool, str]:
        return False, _MOVED

    def refresh_headless_creator(self, **_kwargs) -> tuple[bool, str]:
        return False, _MOVED

    def stop_headless_creator(self) -> tuple[bool, str]:
        return False, _MOVED

    @staticmethod
    def set_headless_refresh_interval(
        *,
        state: PluginStateAccess,
        seconds: int,
    ) -> bool:
        if isinstance(seconds, bool) or not MIN_REFRESH_INTERVAL <= int(seconds) <= MAX_REFRESH_INTERVAL:
            raise ValueError("refresh interval must be between 1 and 24 hours")
        raise RuntimeError(_MOVED)

    @staticmethod
    def headless_creator_status(**_kwargs) -> dict:
        return {"configured": False, "moved_to": "ApplicationService.headless_creator"}

    @staticmethod
    def headless_creator_link() -> str:
        return ""

    @staticmethod
    def headless_creator_due(**_kwargs) -> bool:
        return False


__all__ = [
    "HEADLESS_MAINTENANCE_TASKS",
    "MAX_REFRESH_INTERVAL",
    "MIN_REFRESH_INTERVAL",
    "REFRESH_INTERVAL",
    "REFRESH_INTERVAL_KEY",
    "WdttHeadlessMixin",
    "build_qwdtt_link",
    "due",
    "extract_hash",
    "install",
    "normalize_cookies",
    "setup",
    "stop",
    "uninstall",
]
