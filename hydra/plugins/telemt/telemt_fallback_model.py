"""Configuration model and file codec for Telemt hybrid fallback."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FallbackConfig:
    """User-controlled fallback policy stored in ``[middle_proxy]``."""

    fallback_to_direct: bool = True
    fallback_after_attempts: int = 3
    fallback_after_seconds: int = 45
    auto_revert_to_middle: bool = False

    def __post_init__(self) -> None:
        self.fallback_after_attempts = max(1, min(20, self.fallback_after_attempts))
        self.fallback_after_seconds = max(10, min(300, self.fallback_after_seconds))

    @classmethod
    def defaults(cls) -> FallbackConfig:
        return cls()

    def to_toml_section(self) -> str:
        lines = [
            "",
            "# ── Hybrid fallback: автоматический переход в Direct Mode ──────────",
            "[middle_proxy]",
            "# Разрешить автоматический переход в Direct при недоступности ME-серверов",
            f"fallback_to_direct      = {str(self.fallback_to_direct).lower()}",
            "",
            "# Попыток инициализации ME-пула до признания его недоступным",
            f"fallback_after_attempts = {self.fallback_after_attempts}",
            "",
            "# Максимальное время warmup ME-пула (секунд). При превышении — fallback.",
            f"fallback_after_seconds  = {self.fallback_after_seconds}",
            "",
            "# Автоматический возврат в Middle Proxy после восстановления",
            "# (каркас для будущей реализации; при true — только логирование)",
            f"auto_revert_to_middle   = {str(self.auto_revert_to_middle).lower()}",
        ]
        return "\n".join(lines) + "\n"


def parse_fallback_config(text: str) -> FallbackConfig:
    """Parse the fallback section without performing file I/O."""

    values: dict[str, object] = {}
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[middle_proxy]":
            in_section = True
            continue
        if in_section and stripped.startswith("["):
            break
        if not in_section or not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^(\w+)\s*=\s*(.+)", stripped)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip().lower()
        if key in {"fallback_to_direct", "auto_revert_to_middle"}:
            values[key] = value in {"true", "1", "yes"}
        elif key in {"fallback_after_attempts", "fallback_after_seconds"}:
            try:
                values[key] = int(value)
            except ValueError:
                continue
    return FallbackConfig(**values)


def read_fallback_config(config_file: Path) -> FallbackConfig:
    """Read fallback policy, returning safe defaults for an unreadable file."""

    if not config_file.exists():
        return FallbackConfig()
    try:
        return parse_fallback_config(
            config_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception:
        return FallbackConfig()


def parse_runtime_middle_proxy(text: str) -> bool | None:
    """Read ``use_middle_proxy`` from Telemt TOML text."""

    match = re.search(
        r"^use_middle_proxy\s*=\s*(true|false)",
        text,
        re.MULTILINE | re.IGNORECASE,
    )
    return match.group(1).lower() == "true" if match else None


def read_runtime_middle_proxy(config_file: Path) -> bool | None:
    """Read the runtime transport mode, or ``None`` when it is unavailable."""

    if not config_file.exists():
        return None
    try:
        return parse_runtime_middle_proxy(
            config_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception:
        return None


def render_fallback_section(text: str, fallback: FallbackConfig) -> str:
    """Replace one fallback section while preserving all other TOML sections."""

    output: list[str] = []
    skipping = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[middle_proxy]":
            skipping = True
            continue
        if skipping and stripped.startswith("["):
            skipping = False
        if not skipping:
            output.append(line)
    return "\n".join(output).rstrip() + "\n" + fallback.to_toml_section()


def append_fallback_section(config_file: Path, fallback: FallbackConfig) -> None:
    """Add or replace ``[middle_proxy]`` in an existing Telemt config."""

    if not config_file.exists():
        return
    text = config_file.read_text(encoding="utf-8", errors="replace")
    config_file.write_text(
        render_fallback_section(text, fallback),
        encoding="utf-8",
    )
    config_file.chmod(0o640)
