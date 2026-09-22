"""Снос старого ffmpeg-сервиса живого потока прикрытия.

Раньше здесь жил непрерывный ffmpeg под systemd: он кодировал синтетику или ретранслировал
чужой поток, сжигая CPU. Теперь `/api/media/*` отдаётся чистым reverse_proxy Caddy на живой
HLS-источник (см. `sni_router_http`), поэтому демон не нужен. Модуль оставлен ровно затем,
чтобы снести юнит на уже развёрнутых машинах при следующей установке/удалении.
"""

from __future__ import annotations

from hydra.core import systemd

STREAM_UNIT_NAME = "hydra-vless-cdn-stream"
STREAM_UNIT_SERVICE = f"{STREAM_UNIT_NAME}.service"


def remove_stream_service() -> bool:
    """Снести юнит потока, если он остался от прежней (ffmpeg) версии.

    Идемпотентно: на чистой машине юнита нет — `systemd.remove_unit` это переживает.
    """
    return systemd.remove_unit(STREAM_UNIT_NAME)


__all__ = [
    "STREAM_UNIT_NAME",
    "STREAM_UNIT_SERVICE",
    "remove_stream_service",
]
