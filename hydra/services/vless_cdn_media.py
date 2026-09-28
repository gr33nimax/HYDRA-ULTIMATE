"""Медиа-путь прикрытия как одна операция: поставить, снять, доложить состояние.

Собирает две инфраструктурные части — поток (ffmpeg ремуксит источник в настоящие
сегменты) и сторожа (он отдаёт плейлист и поднимает поток по требованию) — в одно действие
приложения. Здесь же решается, нужен ли поток вообще: фото-режим и пустой источник значат,
что медиа нет, и тогда снимается всё, включая окно сегментов, чтобы на диске не осталось
мусора.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from hydra.contracts.vless_cdn import (
    MEDIA_MODE_VIDEO,
    STREAM_HLS_TIME_DEFAULT,
    STREAM_IDLE_TIMEOUT_DEFAULT,
    STREAM_LIST_SIZE_DEFAULT,
    as_int_or,
    normalize_media_mode,
)


def stream_settings(config: Mapping[str, object]) -> tuple[int, int, int]:
    """Три настройки потока: длительность сегмента, окно плейлиста, простой.

    Границы здесь, а не только в форме ввода: состояние может быть правлено руками, и
    нулевое окно сделало бы поток хрупким независимо от того, как его записали.
    """
    hls_time = max(1, as_int_or(config.get("stream_hls_time"), STREAM_HLS_TIME_DEFAULT))
    list_size = max(2, as_int_or(config.get("stream_hls_list_size"), STREAM_LIST_SIZE_DEFAULT))
    # Ноль здесь — законное значение («не гасить»), поэтому важен именно дефолт, а не ноль.
    idle = max(0, as_int_or(config.get("stream_idle_timeout"), STREAM_IDLE_TIMEOUT_DEFAULT))
    return hls_time, list_size, idle


def wants_video(config: Mapping[str, object]) -> bool:
    """Нужен ли живой поток: только видео-режим и только с заданным источником."""
    if normalize_media_mode(config.get("media_mode")) != MEDIA_MODE_VIDEO:
        return False
    return bool(str(config.get("cam_source_url", "") or "").strip())


def ensure_media(
    config: Mapping[str, object],
    *,
    on_error: Callable[[str], None] | None = None,
) -> bool:
    """Поставить медиа-путь под текущий режим и источник.

    Поток здесь только ставится: поднимает его сторож при первом обращении к плейлисту,
    поэтому включение протокола само по себе источник не тянет. Порядок установки важен —
    сначала поток, потом сторож, иначе сторож окажется без юнита, который он поднимает.
    """
    from hydra.core import vless_cdn_media, vless_cdn_stream

    if not wants_video(config):
        remove_media()
        return True
    source = str(config.get("cam_source_url", "") or "").strip()
    hls_time, list_size, idle = stream_settings(config)
    if not vless_cdn_stream.install(source, hls_time=hls_time, list_size=list_size, on_error=on_error):
        return False
    return vless_cdn_media.install(
        idle_timeout=idle,
        hls_time=hls_time,
        list_size=list_size,
        on_error=on_error,
    )


def remove_media() -> None:
    """Снять медиа целиком. Порядок важен: сначала сторож — иначе он поднимет поток обратно
    при следующем обращении к плейлисту."""
    from hydra.core import vless_cdn_media, vless_cdn_stream

    vless_cdn_media.remove()
    vless_cdn_stream.remove()


def media_status() -> dict[str, object]:
    """Состояние медиа-пути для интерфейса: идёт ли поток и свеж ли плейлист.

    Живёт здесь, а не в меню: чтобы ответить, надо спросить systemd и заглянуть в файл, а
    это привилегированная работа. Интерфейс получает готовые значения.
    """
    from hydra.core import vless_cdn_stream

    try:
        return {
            "active": vless_cdn_stream.is_active(),
            "playlist_age": vless_cdn_stream.playlist_age(),
        }
    except Exception:
        return {"active": False, "playlist_age": None}


__all__ = [
    "ensure_media",
    "media_status",
    "remove_media",
    "stream_settings",
    "wants_video",
]
