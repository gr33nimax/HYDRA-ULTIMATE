"""Named XHTTP transport profiles for VLESS operators."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from hydra.plugins.vless_xhttp.tuning import (
    DEFAULT_MODE,
    effective,
    validate_mode,
)


CUSTOM_PRESET = "custom"


@dataclass(frozen=True)
class Preset:
    """One coherent XHTTP mode and tuning combination."""

    name: str
    label: str
    description: str
    values: dict[str, object]


PRESETS: dict[str, Preset] = {
    "balanced": Preset(
        "balanced",
        "⚖️  Сбалансированный",
        "Значения по умолчанию: устойчивый stream-up",
        {
            "xhttp_mode": "stream-up",
            "xhttp_padding": "100-1000",
            "xhttp_no_sse_header": False,
            "xhttp_max_post_bytes": 1_000_000,
            "xhttp_max_buffered_posts": 30,
            "xhttp_stream_up_secs": "20-80",
            "xhttp_max_header_bytes": 8192,
        },
    ),
    "low_latency": Preset(
        "low_latency",
        "🚀 Низкая задержка",
        "stream-one и малые буферы для игр, SSH и голоса",
        {
            "xhttp_mode": "stream-one",
            "xhttp_padding": "1-64",
            "xhttp_no_sse_header": False,
            "xhttp_max_post_bytes": 262_144,
            "xhttp_max_buffered_posts": 10,
            "xhttp_stream_up_secs": "10-30",
            "xhttp_max_header_bytes": 8192,
        },
    ),
    "stealth": Preset(
        "stealth",
        "🕶️  Максимальная маскировка",
        "Крупный паддинг и длинные сессии против анализа трафика",
        {
            "xhttp_mode": "stream-up",
            "xhttp_padding": "500-2000",
            "xhttp_no_sse_header": False,
            "xhttp_max_post_bytes": 1_000_000,
            "xhttp_max_buffered_posts": 30,
            "xhttp_stream_up_secs": "30-120",
            "xhttp_max_header_bytes": 16384,
        },
    ),
    "cdn": Preset(
        "cdn",
        "🌐 Через CDN и посредников",
        "packet-up без SSE-заголовка для буферизующих прокси",
        {
            "xhttp_mode": "packet-up",
            "xhttp_padding": "100-1000",
            "xhttp_no_sse_header": True,
            "xhttp_max_post_bytes": 500_000,
            "xhttp_max_buffered_posts": 60,
            "xhttp_stream_up_secs": "40-120",
            "xhttp_max_header_bytes": 8192,
        },
    ),
}


def get_preset(name: object) -> Preset:
    """Return one declared preset or reject the operator input."""
    key = str(name or "").strip().lower().replace("-", "_")
    preset = PRESETS.get(key)
    if preset is None:
        allowed = ", ".join(sorted(PRESETS))
        raise ValueError(f"XHTTP preset must be one of: {allowed}")
    return preset


def apply_preset(config: dict[str, object], name: object) -> str:
    """Write one preset into the desired config and return its name."""
    preset = get_preset(name)
    config.update(preset.values)
    return preset.name


def current_preset(config: Mapping[str, object]) -> str:
    """Return the preset matching the desired config, else ``custom``."""
    values = dict(effective(config))
    values["xhttp_mode"] = validate_mode(
        config.get("xhttp_mode", DEFAULT_MODE),
    )
    for preset in PRESETS.values():
        if all(values.get(key) == value for key, value in preset.values.items()):
            return preset.name
    return CUSTOM_PRESET


def preset_label(name: str) -> str:
    """Return the operator-facing label for a preset name."""
    preset = PRESETS.get(name)
    return preset.label if preset else "🛠 Пользовательский"


__all__ = [
    "CUSTOM_PRESET",
    "PRESETS",
    "Preset",
    "apply_preset",
    "current_preset",
    "get_preset",
    "preset_label",
]
