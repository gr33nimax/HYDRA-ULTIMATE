"""Планировщик медиа-потока-заглушки: собирает argv ffmpeg, ничего не исполняя.

Модуль только строит команду — запуск процесса принадлежит host-слою (TSK-03, systemd):
прямой `subprocess` в production-коде разрешён лишь в `hydra/utils/commands.py`. Поэтому
здесь нет ни запуска ffmpeg, ни вызова yt-dlp: `stream_plan` возвращает argv, а резолв
YouTube-потока (`ytdlp_command`) исполняет вызывающий через HostBackend и присылает адрес
назад в `youtube_stream_url`.

Ретрансляция «живого» медиа поверх того же почерка, что VLESS (см.
.kiro/specs/vless-cdn-decoy): источник (4 формы) сводится в локальный HLS, а на любой
сбой — синтетическая сцена, чтобы заглушка никогда не была мёртвой.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hydra.contracts.vless_cdn import (
    DECOY_ROOT,
    MEDIA_PATH_PREFIX,
    MEDIA_SOURCE_RTSP,
    MEDIA_SOURCE_YOUTUBE,
    assert_public_media_source,
    classify_media_source,
    resolve_host,
)

FFMPEG = "ffmpeg"
YTDLP = "yt-dlp"
SYNTHETIC = "synthetic"

# Форму HLS задаёт только этот сегментер, и он один для источника и синтетики: иначе
# переключение между ними было бы видно по разному плейлисту.
HLS_SEGMENT_SECONDS = 4
HLS_LIST_SIZE = 6
HLS_FLAGS = "delete_segments+omit_endlist"

MEDIA_PLAYLIST_NAME = "playlist.m3u8"
MEDIA_SEGMENT_DIR = "seg"
MEDIA_SEGMENT_TEMPLATE = "seg-%05d.ts"

# Картинка под дешёвую вебкамеру: невысокий fps, небольшая сетка, грайн от noise.
FRAME_WIDTH = 1280
FRAME_HEIGHT = 720
FRAME_RATE = 15
VIDEO_CODEC = "libx264"
VIDEO_PRESET = "veryfast"
VIDEO_TUNE = "zerolatency"


@dataclass(frozen=True)
class StreamPlan:
    """Готовая команда ffmpeg и что за форму она отдаёт (или почему ушла на синтетику)."""

    command: list[str]
    kind: str
    synthetic: bool
    reason: str = ""


def media_directory(root: str | Path = DECOY_ROOT) -> Path:
    """Каталог, из которого Caddy отдаёт медиа-семейство как статику."""
    return Path(root) / MEDIA_PATH_PREFIX.lstrip("/")


def ytdlp_command(watch_url: object) -> list[str]:
    """Аргументы yt-dlp, достающие прямой адрес потока; исполняет вызывающий (host-слой)."""
    return [YTDLP, "-f", "best", "-g", "--no-playlist", str(watch_url or "").strip()]


def hls_output_args(output_dir: str | Path) -> list[str]:
    """Сегментер HLS — единый хвост команды для источника и синтетики."""
    base = Path(output_dir)
    playlist = base / MEDIA_PLAYLIST_NAME
    segment = base / MEDIA_SEGMENT_DIR / MEDIA_SEGMENT_TEMPLATE
    return [
        "-c:v",
        VIDEO_CODEC,
        "-preset",
        VIDEO_PRESET,
        "-tune",
        VIDEO_TUNE,
        "-pix_fmt",
        "yuv420p",
        "-an",
        "-f",
        "hls",
        "-hls_time",
        str(HLS_SEGMENT_SECONDS),
        "-hls_list_size",
        str(HLS_LIST_SIZE),
        "-hls_flags",
        HLS_FLAGS,
        "-hls_segment_filename",
        str(segment),
        str(playlist),
    ]


def stream_plan(
    source_url: object,
    *,
    output_dir: str | Path,
    region: str = "",
    cam_id: str = "",
    seed: str = "",
    youtube_stream_url: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    resolve: Callable[[str], list[str]] = resolve_host,
) -> StreamPlan:
    """Выбрать форму источника и собрать argv; на любую непригодность — синтетика.

    Возвращает всегда пригодный план: заглушка не должна оставаться без потока из-за
    пустого, приватного или неразрешимого источника. Причину отказа несёт `reason`.
    ``which`` и ``resolve`` инжектируемы: тесты не ходят ни в PATH, ни в DNS.
    """

    def synthetic(reason: str) -> StreamPlan:
        return _synthetic_plan(output_dir, region=region, cam_id=cam_id, seed=seed, reason=reason)

    raw = str(source_url or "").strip()
    if not raw:
        return synthetic("")

    try:
        kind = classify_media_source(raw)
        assert_public_media_source(raw, resolve=resolve)
    except ValueError as exc:
        return synthetic(f"источник отклонён: {exc}")

    if kind == MEDIA_SOURCE_YOUTUBE:
        if which(YTDLP) is None:
            return synthetic("yt-dlp недоступен: форма YouTube отклонена")
        resolved = str(youtube_stream_url or "").strip()
        if not resolved:
            return synthetic("адрес YouTube-потока не разрешён")
        try:
            assert_public_media_source(resolved, resolve=resolve)
        except ValueError as exc:
            return synthetic(f"адрес YouTube-потока отклонён: {exc}")
        url = resolved
    else:
        url = raw

    return StreamPlan(
        command=_command(_source_input_args(url, kind), output_dir),
        kind=kind,
        synthetic=False,
    )


def _command(input_args: list[str], output_dir: str | Path) -> list[str]:
    return [
        FFMPEG,
        "-hide_banner",
        "-loglevel",
        "warning",
        "-nostdin",
        *input_args,
        *hls_output_args(output_dir),
    ]


def _source_input_args(url: str, kind: str) -> list[str]:
    if kind == MEDIA_SOURCE_RTSP:
        # TCP, а не UDP: по UDP RTSP теряет пакеты и залипает на мобильных/чужих сетях.
        return ["-rtsp_transport", "tcp", "-i", url]
    # http(s) HLS и MJPEG: переподключение, чтобы пропавший источник не застопорил заглушку.
    return [
        "-reconnect",
        "1",
        "-reconnect_streamed",
        "1",
        "-reconnect_delay_max",
        "5",
        "-i",
        url,
    ]


def _synthetic_plan(
    output_dir: str | Path,
    *,
    region: str,
    cam_id: str,
    seed: str,
    reason: str,
) -> StreamPlan:
    input_args = ["-f", "lavfi", "-i", synthetic_graph(region=region, cam_id=cam_id, seed=seed)]
    return StreamPlan(
        command=_command(input_args, output_dir),
        kind=SYNTHETIC,
        synthetic=True,
        reason=reason,
    )


def synthetic_graph(*, region: str = "", cam_id: str = "", seed: str = "") -> str:
    """Процедурная сцена «уличной камеры»: фон, движение, грайн и живое время.

    Никаких внешних файлов: всё генерит ffmpeg. seed задаёт cam-id, амплитуду оттенка и
    уровень грайна, поэтому два разных домена не дают байт-в-байт одинаковую сцену.
    """
    salt = _seed_int(seed)
    hue_amplitude = 0.10 + (salt % 40) / 400.0
    noise = 10 + (salt % 12)
    camera = _filter_text(cam_id) or f"CAM-{salt % 10000:04d}"
    city = _filter_text(region)

    parts = [
        f"color=c=0x161b22:s={FRAME_WIDTH}x{FRAME_HEIGHT}:r={FRAME_RATE}",
        f"noise=alls={noise}:allf=t+u",
        f"hue=H='{hue_amplitude:.3f}*sin(t/9)'",
        _drawtext("LIVE", x=20, y=20, size=28, colour="red"),
        _drawtext("%{localtime\\:%X}", x=20, y=60, size=24, colour="white"),
        _drawtext(camera, x=20, y=100, size=20, colour="0x9fb0c0"),
    ]
    if city:
        parts.append(_drawtext(city, x=20, y=132, size=20, colour="0x9fb0c0"))
    parts.append("format=yuv420p")
    return ",".join(parts)


def _drawtext(text: str, *, x: int, y: int, size: int, colour: str) -> str:
    return f"drawtext=text='{text}':x={x}:y={y}:fontcolor={colour}:fontsize={size}"


def _seed_int(seed: str) -> int:
    return int(hashlib.sha256(str(seed or "").encode("utf-8")).hexdigest()[:8], 16)


def _filter_text(value: object) -> str:
    """Оставить только безопасные для фильтр-графа символы: без «:», кавычек и «{}»."""
    safe = "".join(character for character in str(value or "") if character.isalnum() or character in " -_.")
    return safe.strip()[:48]


__all__ = [
    "MEDIA_PLAYLIST_NAME",
    "MEDIA_SEGMENT_DIR",
    "MEDIA_SEGMENT_TEMPLATE",
    "SYNTHETIC",
    "StreamPlan",
    "hls_output_args",
    "media_directory",
    "stream_plan",
    "synthetic_graph",
    "ytdlp_command",
]
