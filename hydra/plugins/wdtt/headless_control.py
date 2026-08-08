"""Runtime controls for the four qWDTT creator instances."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.wdtt.model import WdttEnvironment


def service_names(env: WdttEnvironment) -> list[str]:
    return [
        f"wdtt-headless-creator@{index}.service"
        for index in range(1, env.headless_call_count + 1)
    ]


def call_files(env: WdttEnvironment) -> list[Path]:
    return [
        env.headless_dir / f"{index}.call.txt"
        for index in range(1, env.headless_call_count + 1)
    ]


def stop(env: WdttEnvironment) -> tuple[bool, str]:
    """Retain the legacy signature without performing host mutations."""
    del env
    return False, "VK creator management moved to ApplicationService.headless_creator"


__all__ = ["call_files", "service_names", "stop"]
