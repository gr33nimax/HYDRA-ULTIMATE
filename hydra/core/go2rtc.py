"""Локальный ретранслятор go2rtc: тянет любой источник (rtsp/hls/mjpeg) и отдаёт HLS.

`/api/media/*` декой-сайта проксируется Caddy'ем на этот go2rtc (127.0.0.1:1984), поэтому
плеер сайта всегда ходит на наш домен, а go2rtc server-side достаёт камеру. Без ffmpeg-энкода:
go2rtc ремуксит H264 и тянет апстрим только когда есть зритель (on-demand).

Бинарь ставится пином версии из GitHub releases с проверкой SHA-256 (digest из метаданных
релиза). API прибит к localhost, RTSP — тоже (нужен только как внутренний транспорт для
`ffmpeg:`-источников), WebRTC/SRTP выключены — наружу ничего не торчит.
"""

from __future__ import annotations

import tempfile
import contextlib
from collections.abc import Callable
from pathlib import Path

from hydra.contracts.vless_cdn import (
    GO2RTC_API_HOST,
    GO2RTC_API_PORT,
    GO2RTC_STREAM_NAME,
    source_needs_ffmpeg,
)
from hydra.core import systemd
from hydra.core.host import HOST

GO2RTC_REPO = "AlexxIT/go2rtc"
# Пин версии: обновляется правкой этой строки, не «latest» — чужой бинарь на VPS.
# v1.9.14+ — у ассетов есть SHA-256 digest в метаданных (старые релизы его не несли,
# и require_digest их бы отклонил).
GO2RTC_VERSION = "v1.9.14"
GO2RTC_BIN = Path("/usr/local/bin/go2rtc")
GO2RTC_CONFIG = Path("/etc/hydra/go2rtc.yaml")
GO2RTC_UNIT_NAME = "hydra-go2rtc"
GO2RTC_UNIT_SERVICE = f"{GO2RTC_UNIT_NAME}.service"

# RTSP-сервер go2rtc — внутренний транспорт для `ffmpeg:`-источников: go2rtc запускает
# ffmpeg в режиме exec, а тот пишет результат в собственный RTSP-сервер (шаблон вывода
# содержит `{output}`), и без него источник падает с "exec: rtsp module disabled".
# Слушаем только loopback — наружу порт не смотрит.
GO2RTC_RTSP_HOST = "127.0.0.1"
GO2RTC_RTSP_PORT = 8554

# Источник с префиксом `ffmpeg:` уводит разбор на ffmpeg (родной HLS-ридер go2rtc падает
# на корректных манифестах: CRLF в строках сегментов, fMP4). Бинарь берём сборкой BtbN, а
# не дистрибутивом: go2rtc пропускает только ffmpeg >= 5.0 (сравнивает libavformat >=
# 59.16), а в jammy 22.04 лежит 4.4.2 с 58.76 — apt-версия отвергается.
# Пин — имя ассета, а не тег: BtbN чистит старые autobuild-релизы, а stable-линия в
# релизе `latest` живёт долго. Диггест ассета обязателен (require_digest).
FFMPEG_REPO = "BtbN/FFmpeg-Builds"
FFMPEG_ASSETS = {
    "amd64": "ffmpeg-n9.0-latest-linux64-lgpl-9.0.tar.xz",
    "arm64": "ffmpeg-n9.0-latest-linuxarm64-lgpl-9.0.tar.xz",
}
FFMPEG_BIN = Path("/usr/local/bin/ffmpeg")
# Статический ffmpeg ~80 МБ; порог ловит обрезанную загрузку и html-заглушку.
FFMPEG_MIN_BIN_SIZE = 20_000_000

# Минимальный порог размера ELF, чтобы не принять html-заглушку за бинарь.
_MIN_BIN_SIZE = 1_000_000


def _yaml_quote(value: str) -> str:
    """Заключить скаляр в двойные кавычки для YAML: URL содержит «:», «?», «&»."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_config(source_url: str) -> str:
    """go2rtc.yaml: один поток `decoy` из источника; всё слушает только loopback.

    Пустой источник тоже валиден: поток объявлен без адреса (go2rtc это допускает),
    просто отдавать нечего, пока источник не задан.
    """
    source = str(source_url).strip()
    source_line = f"  {GO2RTC_STREAM_NAME}: {_yaml_quote(source)}" if source else f"  {GO2RTC_STREAM_NAME}:"
    return (
        "api:\n"
        f'  listen: "{GO2RTC_API_HOST}:{GO2RTC_API_PORT}"\n'
        # RTSP — только loopback: он нужен `ffmpeg:`-источникам как приёмник (см. выше),
        # и без него такой источник не стартует вовсе.
        "rtsp:\n"
        f'  listen: "{GO2RTC_RTSP_HOST}:{GO2RTC_RTSP_PORT}"\n'
        "webrtc:\n"
        '  listen: ""\n'
        "srtp:\n"
        '  listen: ""\n'
        "log:\n"
        "  level: warn\n"
        # Путь к бинарю прописан явно: без этого go2rtc берёт первый `ffmpeg` из PATH,
        # а там может оказаться дистрибутивный — он ниже его порога версии.
        "ffmpeg:\n"
        # as_posix: конфиг обязан нести POSIX-путь независимо от того, где его собрали.
        f"  bin: {FFMPEG_BIN.as_posix()}\n"
        "streams:\n"
        f"{source_line}\n"
    )


def _unit() -> str:
    return f"""[Unit]
Description=HYDRA go2rtc restreamer (decoy media)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={GO2RTC_BIN} -config {GO2RTC_CONFIG}
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={GO2RTC_CONFIG.parent}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def ensure_binary(*, on_error: Callable[[str], None] | None = None) -> bool:
    """Скачать пинованный go2rtc для нашей арки с проверкой SHA-256; пропустить, если уже есть.

    Идентичность релиза подтверждается digest'ом из метаданных GitHub (require_digest),
    а не голым TLS: подменённый ассет не пройдёт. ELF-проверка отсекает html/заглушки.
    `on_error` (коллбек str->None) прокидывается в загрузчик, чтобы причина сбоя была видна.
    """
    if GO2RTC_BIN.exists() and GO2RTC_BIN.stat().st_size > _MIN_BIN_SIZE:
        return True
    from hydra.utils.downloader import download_github_asset_filtered, verify_elf
    from hydra.utils.net import detect_arch

    arch = detect_arch()  # "amd64" | "arm64"
    asset = f"go2rtc_linux_{arch}"
    with tempfile.TemporaryDirectory(prefix="hydra-go2rtc-") as directory:
        binary = Path(directory) / "go2rtc"
        if not download_github_asset_filtered(
            GO2RTC_REPO,
            lambda name: name == asset,
            binary,
            release_tag=GO2RTC_VERSION,
            require_unique=True,
            require_digest=True,
            on_error=on_error,
        ):
            return False
        if binary.stat().st_size <= _MIN_BIN_SIZE or not verify_elf(binary):
            return False
        binary.chmod(0o755)
        HOST.atomic_copy(binary, GO2RTC_BIN, mode=0o755)
    return True


def _fail(on_error: Callable[[str], None] | None, message: str) -> None:
    if on_error is not None:
        on_error(message)


def ensure_ffmpeg(*, on_error: Callable[[str], None] | None = None) -> bool:
    """Положить пинованный статический ffmpeg в /usr/local/bin, если источника без него нет.

    Без бинаря go2rtc молча не отдаёт видео: ошибка ffmpeg-продюсера видна только в логе,
    а плеер стоит пустой. Поэтому отказ явный, с причиной в `on_error`.

    Проверяем именно свой путь, а не наличие `ffmpeg` в PATH: дистрибутивный бинарь
    может быть старше порога go2rtc, и повторять его разбор версии здесь — лишняя
    догадка, которая разъедется с ядром. Свой бинарь всегда тот, что нужен, и в PATH он
    раньше `/usr/bin`; в go2rtc.yaml путь прописан явно (`bin`).
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


def write_config(source_url: str) -> None:
    """Записать go2rtc.yaml с текущим источником (idempotent)."""
    GO2RTC_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    HOST.atomic_write(GO2RTC_CONFIG, render_config(source_url), mode=0o644)


def install(source_url: str, *, on_error: Callable[[str], None] | None = None) -> bool:
    """Поставить бинарь, записать конфиг, поднять сервис. Без бинаря — фейл-клоуз."""
    if not ensure_binary(on_error=on_error):
        return False
    if source_needs_ffmpeg(source_url) and not ensure_ffmpeg(on_error=on_error):
        return False
    write_config(source_url)
    if not systemd.install_service(GO2RTC_UNIT_NAME, _unit()):
        return False
    return systemd.start(GO2RTC_UNIT_SERVICE)


def apply_source(source_url: str, *, on_error: Callable[[str], None] | None = None) -> bool:
    """Сменить источник: перезаписать конфиг и перезапустить go2rtc.

    Перезапуск, а не reload: on-demand-сессии дешёвые, а SIGHUP go2rtc не гарантирует
    подхват смены streams во всех версиях — перезапуск предсказуем.
    """
    if not GO2RTC_BIN.exists() and not install(source_url, on_error=on_error):
        return False
    if source_needs_ffmpeg(source_url) and not ensure_ffmpeg(on_error=on_error):
        return False
    write_config(source_url)
    return systemd.restart(GO2RTC_UNIT_SERVICE)


def remove() -> bool:
    """Снести сервис и конфиг. Бинарь оставляем — он общий и безвредный."""
    removed = systemd.remove_unit(GO2RTC_UNIT_NAME)
    with contextlib.suppress(OSError):
        GO2RTC_CONFIG.unlink(missing_ok=True)
    return removed


__all__ = [
    "FFMPEG_ASSETS",
    "FFMPEG_BIN",
    "FFMPEG_MIN_BIN_SIZE",
    "FFMPEG_REPO",
    "GO2RTC_BIN",
    "GO2RTC_CONFIG",
    "GO2RTC_REPO",
    "GO2RTC_RTSP_HOST",
    "GO2RTC_RTSP_PORT",
    "GO2RTC_UNIT_NAME",
    "GO2RTC_UNIT_SERVICE",
    "GO2RTC_VERSION",
    "apply_source",
    "ensure_binary",
    "ensure_ffmpeg",
    "install",
    "remove",
    "render_config",
    "write_config",
]
