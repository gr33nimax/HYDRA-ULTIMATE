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
    purpose: str
    values: dict[str, object]

    @property
    def title(self) -> str:
        """Return the label without decoration, for aligned status cards."""
        return self.label.split(" ", 1)[-1].strip()

    @property
    def details(self) -> str:
        """Return the exact values this profile writes."""
        return " · ".join(
            (
                str(self.values["xhttp_mode"]),
                f"padding {self.values['xhttp_padding']} Б",
                f"post {self.values['xhttp_max_post_bytes']} Б",
                f"буфер {self.values['xhttp_max_buffered_posts']}",
                f"сессия {self.values['xhttp_stream_up_secs']} с",
            ),
        )

    @property
    def description(self) -> str:
        """Return the operator-facing line: why, then what exactly."""
        return f"{self.purpose} — {self.details}"


PRESETS: dict[str, Preset] = {
    "balanced": Preset(
        "balanced",
        "⚖️  Сбалансированный",
        "Значения по умолчанию sing-box, устойчивы на нестабильном канале",
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
        "Один поток и малые буферы: меньше задержка, выше накладные расходы",
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
        "Крупный паддинг и длинные сессии против анализа размеров и частоты",
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


def preset_title(name: str) -> str:
    """Return the undecorated preset name used in aligned status cards."""
    preset = PRESETS.get(name)
    return preset.title if preset else "пользовательский"


__all__ = [
    "CUSTOM_PRESET",
    "PRESETS",
    "Preset",
    "apply_preset",
    "current_preset",
    "get_preset",
    "preset_label",
    "preset_title",
]
