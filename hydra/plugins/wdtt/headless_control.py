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
    """End all creator calls and invalidate the now-stale master link."""
    failures: list[str] = []
    for unit in service_names(env):
        for action in ("stop", "disable"):
            result = env.host.run(
                ["systemctl", action, unit],
                capture_output=True,
            )
            if result.returncode != 0:
                failures.append(f"{action} {unit}")
    for path in (*call_files(env), env.headless_link_file):
        env.host.remove_file(path, missing_ok=True)
    if failures:
        return False, "failed to stop all creator services: " + ", ".join(failures)
    return True, "all VK creator calls stopped"


__all__ = ["call_files", "service_names", "stop"]
