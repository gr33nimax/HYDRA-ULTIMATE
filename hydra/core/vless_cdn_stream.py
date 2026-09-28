"""Живой HLS-поток прикрытия: ffmpeg ремуксит источник в настоящие сегменты.

Почему ffmpeg, а не go2rtc. Его HLS-выход не сегментирует: он отдаёт «всё, что накопилось
с прошлого чтения», и объявляет это полусекундой видео (`#EXTINF:0.500`), а параметр `n` в
запросе сегмента вообще игнорируется. Настоящие данные приходят редко и пачкой, медиана
ответа — 376 байт. Плеер строит таймлайн по `EXTINF`, уезжает вдвое и встаёт — при живом
сервисе и здоровом источнике. Проверено на боевом сервере: 4 сегмента в секунду по 376
байт, окно в две записи.

ffmpeg пишет настоящие длительности, держит окно в десятки секунд и отдаёт сегменты как
файлы: их можно перезапросить, отложить, распараллелить — вернутся те же байты.

Сам ffmpeg запускается **по требованию**: его поднимает сторож `hydra-vless-cdn-media`
при первом обращении к плейлисту и гасит по простою. Здесь — только процесс, юнит и его
жизненный цикл; раздача файлов остаётся за Caddy (статический маршрут уже есть).
"""

from __future__ import annotations

import contextlib
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from hydra.contracts.vless_cdn import (
    DECOY_ROOT,
    MEDIA_SEGMENT_PATH_PREFIX,
    MEDIA_SOURCE_RTSP,
    classify_media_source,
    strip_source_prefix,
)
from hydra.core import systemd
from hydra.core.host import HOST

STREAM_UNIT_NAME = "hydra-vless-cdn-stream"
STREAM_UNIT_SERVICE = f"{STREAM_UNIT_NAME}.service"

# Сборка BtbN: дистрибутивный ffmpeg jammy (4.4.2) для нашей задачи не годится, потому что
# тянет за собой кучу лишнего и не пинуется. Пин — имя ассета, а не тег: BtbN чистит
# старые autobuild-релизы, а stable-линия в релизе `latest` живёт долго.
FFMPEG_REPO = "BtbN/FFmpeg-Builds"
FFMPEG_ASSETS = {
    "amd64": "ffmpeg-n9.0-latest-linux64-lgpl-9.0.tar.xz",
    "arm64": "ffmpeg-n9.0-latest-linuxarm64-lgpl-9.0.tar.xz",
}
FFMPEG_BIN = Path("/usr/local/bin/ffmpeg")
# Статический ffmpeg ~140 МБ; порог ловит обрезанную загрузку и html-заглушку.
FFMPEG_MIN_BIN_SIZE = 20_000_000

MEDIA_DIR = Path(DECOY_ROOT) / "api" / "media"
SEGMENT_DIR = MEDIA_DIR / "seg"
PLAYLIST_PATH = MEDIA_DIR / "playlist.m3u8"

HLS_DELETE_THRESHOLD = 3
# temp_file: плейлист пишется во временный файл и переименовывается, иначе плеер может
# прочитать половину. omit_endlist: плейлист живой, без признака конца.
HLS_FLAGS = "delete_segments+omit_endlist+temp_file"
# Нумерация от эпохи: при перезапуске ffmpeg последовательность не сбрасывается, и имена
# сегментов не совпадают с прежними — иначе плеер взял бы из кеша чужое содержимое.
HLS_START_NUMBER_SOURCE = "epoch"
# Сегменты прошлых запусков ffmpeg не удаляет: он чистит только то, что выпало из его
# собственного плейлиста. Поэтому сметаем их сами при старте.
ORPHAN_AGE_MINUTES = 5
# RTSP без явного таймаута висит на мёртвой камере бесконечно (микросекунды).
RTSP_TIMEOUT_US = 10_000_000

# Юнит, оставшийся от прежней ретрансляции через go2rtc. Снимаем при установке потока,
# чтобы на сервере не жили две ретрансляции одновременно.
LEGACY_UNITS = ("hydra-go2rtc",)


def _fail(on_error: Callable[[str], None] | None, message: str) -> None:
    if on_error is not None:
        on_error(message)


def segment_base_url() -> str:
    """Ссылка на сегменты относительно плейлиста — `seg/`.

    Выводится из контракта, а не пишется руками: плейлист лежит в `/api/media/`, сегменты
    в `/api/media/seg/`, и Caddy раздаёт их по этому же префиксу.
    """
    return Path(MEDIA_SEGMENT_PATH_PREFIX).name + "/"


def build_command(
    source: str,
    *,
    hls_time: int,
    list_size: int,
    binary: Path | None = None,
    playlist: Path | None = None,
    segments: Path | None = None,
) -> list[str]:
    """Команда ffmpeg: ремукс источника в живой HLS с настоящими длительностями.

    `hls_time` — только минимум. Резать можно лишь по кейфреймам, поэтому реальная
    длительность сегмента не меньше интервала между ними: у источника с кейфреймом в 3 с
    выйдет 3 с, сколько ни проси. Это не ошибка настройки, а свойство ремукса.
    """
    url = strip_source_prefix(source)
    kind = classify_media_source(url)
    if kind == MEDIA_SOURCE_RTSP:
        # UDP за NAT теряется, а без таймаута процесс висит на мёртвой камере.
        input_args = ["-rtsp_transport", "tcp", "-timeout", str(RTSP_TIMEOUT_US)]
    else:
        # Источник может икнуть: переподключаемся вместо выхода, иначе рвётся окно
        # сегментов и плеер получает провал вместо паузы.
        input_args = ["-reconnect", "1", "-reconnect_streamed", "1", "-reconnect_delay_max", "5"]
    return [
        # as_posix: в юнит и в команду обязан попасть POSIX-путь, где бы её ни собрали.
        (binary or FFMPEG_BIN).as_posix(),
        # Без -nostdin ffmpeg читает команды со stdin и съедает чужой ввод: под systemd
        # это ломает запуск, а при ручной проверке — половину скрипта.
        "-nostdin",
        "-hide_banner",
        "-v",
        "warning",
        "-fflags",
        "nobuffer",
        "-flags",
        "low_delay",
        *input_args,
        "-i",
        url,
        # Ремукс, не перекодирование: ни одного процента на кодек.
        "-c",
        "copy",
        "-f",
        "hls",
        "-hls_time",
        str(hls_time),
        "-hls_list_size",
        str(list_size),
        "-hls_delete_threshold",
        str(HLS_DELETE_THRESHOLD),
        "-hls_flags",
        HLS_FLAGS,
        "-hls_segment_type",
        "mpegts",
        "-hls_start_number_source",
        HLS_START_NUMBER_SOURCE,
        "-hls_segment_filename",
        ((segments or SEGMENT_DIR) / "s%d.ts").as_posix(),
        "-hls_base_url",
        segment_base_url(),
        (playlist or PLAYLIST_PATH).as_posix(),
    ]


def _quote(value: str) -> str:
    """Экранировать аргумент для ExecStart.

    systemd разбирает ExecStart сам, а не через шелл, и вдобавок раскрывает в нём
    спецификаторы: управляющий символ — это `%` (`%d` — каталог credentials), поэтому его
    надо удваивать. Без этого `-hls_segment_filename …/s%d.ts` превращает юнит в
    `bad-setting`, и служба не стартует вовсе — сама и без единой строки в журнале ffmpeg.
    """
    text = str(value).replace("%", "%%")
    if not any(character in text for character in ' \t"\\'):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_unit(
    command: list[str],
    *,
    media_dir: Path | None = None,
    segments: Path | None = None,
) -> str:
    """Юнит потока. Без секции `[Install]` — поднимается по требованию, не на загрузке.

    `ReadWritePaths` указывает ровно на каталог окна: `ProtectSystem=strict` оставляет
    остальную файловую систему только для чтения, и без этого ffmpeg не запишет сегменты.
    """
    directory = (media_dir or MEDIA_DIR).as_posix()
    segment_directory = (segments or SEGMENT_DIR).as_posix()
    exec_line = " ".join(_quote(argument) for argument in command)
    return f"""[Unit]
Description=HYDRA VLESS CDN decoy media stream (ffmpeg remux)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/find {segment_directory} -type f -name '*.ts' -mmin +{ORPHAN_AGE_MINUTES} -delete
ExecStart={exec_line}
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={directory}
ProtectHome=true
PrivateTmp=true
"""


def ensure_directories(
    *,
    media_dir: Path | None = None,
    segments: Path | None = None,
) -> None:
    """Каталог окна сегментов должен существовать до старта: иначе ReadWritePaths мимо."""
    (media_dir or MEDIA_DIR).mkdir(parents=True, exist_ok=True)
    (segments or SEGMENT_DIR).mkdir(parents=True, exist_ok=True)


def ensure_ffmpeg(*, on_error: Callable[[str], None] | None = None) -> bool:
    """Положить пинованную статическую сборку ffmpeg, если её ещё нет.

    Проверяем именно свой путь, а не наличие `ffmpeg` в PATH: дистрибутивный бинарь может
    не подойти, а разбор его версии здесь — лишняя догадка, которая разъедется с реальностью.
    """
    if FFMPEG_BIN.exists() and FFMPEG_BIN.stat().st_size > FFMPEG_MIN_BIN_SIZE:
        return True
    from hydra.utils.downloader import download_github_asset_filtered, extract_tarball, verify_elf
    from hydra.utils.net import detect_arch

    arch = detect_arch()
    asset = FFMPEG_ASSETS.get(arch)
    if asset is None:
        _fail(on_error, f"нет сборки ffmpeg под архитектуру {arch}")
        return False
    with tempfile.TemporaryDirectory(prefix="hydra-ffmpeg-") as directory:
        archive = Path(directory) / "ffmpeg.tar.xz"
        if not download_github_asset_filtered(
            FFMPEG_REPO,
            lambda name: name == asset,
            archive,
            require_unique=True,
            require_digest=True,
            on_error=on_error,
        ):
            return False
        unpacked = extract_tarball(archive, Path(directory) / "unpacked")
        candidates = sorted(unpacked.glob("*/bin/ffmpeg"))
        if len(candidates) != 1:
            _fail(on_error, f"в архиве ffmpeg ожидался один бинарь, найдено {len(candidates)}")
            return False
        binary = candidates[0]
        if binary.stat().st_size <= FFMPEG_MIN_BIN_SIZE or not verify_elf(binary):
            _fail(on_error, "ffmpeg из архива не похож на ELF-бинарь")
            return False
        binary.chmod(0o755)
        HOST.atomic_copy(binary, FFMPEG_BIN, mode=0o755)
    return True


def install(
    source: str,
    *,
    hls_time: int,
    list_size: int,
    on_error: Callable[[str], None] | None = None,
) -> bool:
    """Поставить бинарь, каталоги и юнит. Без ffmpeg — фейл-клоуз.

    Юнит намеренно не включается: поток поднимает сторож по первому обращению. Прежнюю
    ретрансляцию через go2rtc снимаем здесь же, иначе на сервере окажутся две.
    """
    if not ensure_ffmpeg(on_error=on_error):
        return False
    ensure_directories()
    for legacy in LEGACY_UNITS:
        systemd.remove_unit(legacy)
    command = build_command(source, hls_time=hls_time, list_size=list_size)
    if not systemd.install_service(STREAM_UNIT_NAME, render_unit(command), enable=False):
        _fail(on_error, "не удалось установить юнит потока")
        return False
    return True


def apply_source(
    source: str,
    *,
    hls_time: int,
    list_size: int,
    on_error: Callable[[str], None] | None = None,
) -> bool:
    """Переписать команду под новый источник и перезапустить поток, если он идёт.

    Спящий поток не будим: его поднимет сторож при следующем обращении к плейлисту.
    """
    if not install(source, hls_time=hls_time, list_size=list_size, on_error=on_error):
        return False
    if systemd.is_active(STREAM_UNIT_SERVICE):
        return systemd.restart(STREAM_UNIT_SERVICE)
    return True


def start() -> bool:
    """Поднять поток (сторож вызывает это на первом обращении)."""
    return systemd.start(STREAM_UNIT_SERVICE)


def stop() -> bool:
    """Погасить поток (сторож вызывает это по простою)."""
    return systemd.stop(STREAM_UNIT_SERVICE)


def is_active() -> bool:
    return systemd.is_active(STREAM_UNIT_SERVICE)


def playlist_age() -> float | None:
    """Сколько секунд плейлисту. None — файла нет: поток ещё не успел или не поднялся."""
    try:
        return max(0.0, time.time() - PLAYLIST_PATH.stat().st_mtime)
    except OSError:
        return None


def remove() -> bool:
    """Снести юнит и окно сегментов: медиа-эндпоинт остаётся пустым, как и решено."""
    removed = systemd.remove_unit(STREAM_UNIT_NAME)
    with contextlib.suppress(OSError):
        for leftover in SEGMENT_DIR.glob("*.ts"):
            leftover.unlink()
    with contextlib.suppress(OSError):
        PLAYLIST_PATH.unlink(missing_ok=True)
    return removed


__all__ = [
    "FFMPEG_ASSETS",
    "FFMPEG_BIN",
    "FFMPEG_MIN_BIN_SIZE",
    "FFMPEG_REPO",
    "MEDIA_DIR",
    "PLAYLIST_PATH",
    "SEGMENT_DIR",
    "STREAM_UNIT_NAME",
    "STREAM_UNIT_SERVICE",
    "apply_source",
    "build_command",
    "ensure_directories",
    "ensure_ffmpeg",
    "install",
    "is_active",
    "playlist_age",
    "remove",
    "render_unit",
    "segment_base_url",
    "start",
    "stop",
]
