"""Dependency-free smoke tests for ``python telemt_fallback.py --test``."""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import ModuleType


def run(api: ModuleType) -> None:
    """Exercise the compatibility facade without invoking system services."""

    failures: list[str] = []
    passed = 0

    def check(condition: bool, label: str) -> None:
        nonlocal passed
        if condition:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failures.append(label)
            print(f"  FAIL  {label}")

    fallback = api.FallbackConfig.defaults()
    check(fallback.fallback_to_direct is True, "safe defaults")
    check(fallback.fallback_after_attempts == 3, "default attempts")
    check(fallback.fallback_after_seconds == 45, "default timeout")

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".toml",
        delete=False,
    ) as stream:
        stream.write(
            "[general]\n"
            "use_middle_proxy = true\n\n"
            "[middle_proxy]\n"
            "fallback_to_direct = false\n"
            "fallback_after_attempts = 7\n"
            "fallback_after_seconds = 60\n"
        )
        path = Path(stream.name)
    try:
        parsed = api.read_fallback_config(path)
        check(parsed.fallback_to_direct is False, "policy parsing")
        check(parsed.fallback_after_attempts == 7, "attempt parsing")
        check(api.read_runtime_middle_proxy(path) is True, "runtime parsing")
        api.append_fallback_section(path, api.FallbackConfig())
        check(
            path.read_text().count("[middle_proxy]") == 1,
            "section replacement",
        )
        check(
            api._patch_config_middle_proxy(path, enable=False),
            "runtime patch",
        )
        check(
            "use_middle_proxy = false" in path.read_text(),
            "direct mode rendering",
        )
    finally:
        path.unlink(missing_ok=True)

    if failures:
        raise SystemExit(f"FAILED: {len(failures)} self-test(s)")
    print(f"All {passed} fallback self-tests passed")
