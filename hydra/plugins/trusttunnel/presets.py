"""hydra/plugins/trusttunnel/presets.py — Пресеты обфускации TrustTunnel."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TrustTunnelPreset:
    """Пресет конфигурации TrustTunnel."""
    name: str
    label: str
    description: str
    transport: str                        # "tcp" | "quic" | "both"
    alpn: list[str] = field(default_factory=lambda: ["h2"])
    utls_fingerprint: str | None = None   # chrome | firefox | safari | edge | randomized | None
    multiplex: dict | None = None         # {"protocol": "h2mux", "max_connections": 4, ...}
    padding: bool = False                 # multiplex padding


PRESETS: dict[str, TrustTunnelPreset] = {
    "default": TrustTunnelPreset(
        name="default",
        label="🌐 Стандартный",
        description="Базовый HTTP/2 туннель, максимальная совместимость",
        transport="tcp",
        alpn=["h2"],
        utls_fingerprint=None,
        multiplex=None,
        padding=False,
    ),
    "stealth": TrustTunnelPreset(
        name="stealth",
        label="🥷 Стелс",
        description="Chrome fingerprint + мультиплексирование + padding",
        transport="tcp",
        alpn=["h2"],
        utls_fingerprint="chrome",
        multiplex={"protocol": "h2mux", "max_connections": 4, "min_streams": 2, "max_streams": 0},
        padding=True,
    ),
    "fortress": TrustTunnelPreset(
        name="fortress",
        label="🏰 Крепость",
        description="Максимальная обфускация: рандом fingerprint, yamux, padding, TCP Brutal",
        transport="tcp",
        alpn=["h2"],
        utls_fingerprint="randomized",
        multiplex={
            "protocol": "yamux",
            "max_connections": 8,
            "min_streams": 4,
            "max_streams": 0,
            "brutal": {"enabled": True, "up_mbps": 50, "down_mbps": 100},
        },
        padding=True,
    ),
}



def list_presets() -> list[dict]:
    """Возвращает список пресетов для UI."""
    return [
        {
            "name": p.name,
            "label": p.label,
            "description": p.description,
            "transport": p.transport,
        }
        for p in PRESETS.values()
    ]


def get_preset(name: str) -> TrustTunnelPreset:
    """Возвращает пресет по имени, fallback на 'default'."""
    return PRESETS.get(name, PRESETS["default"])


def validate_preset(name: str) -> bool:
    """Проверяет существование пресета."""
    return name in PRESETS
