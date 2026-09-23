"""Локальный ретранслятор go2rtc: тянет любой источник (rtsp/hls/mjpeg) и отдаёт HLS.

`/api/media/*` декой-сайта проксируется Caddy'ем на этот go2rtc (127.0.0.1:1984), поэтому
плеер сайта всегда ходит на наш домен, а go2rtc server-side достаёт камеру. Без ffmpeg-энкода:
go2rtc ремуксит H264 и тянет апстрим только когда есть зритель (on-demand).

Бинарь ставится пином версии из GitHub releases с проверкой SHA-256 (digest из метаданных
релиза). API прибит к localhost, RTSP/WebRTC-серверы go2rtc выключены — наружу ничего не торчит.
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

# Пакет для источников с префиксом `ffmpeg:`: родной HLS-ридер go2rtc падает на корректных
# манифестах (CRLF в строках сегментов, fMP4), и такой источник уводится на разбор ffmpeg'у.
FFMPEG_PACKAGE = "ffmpeg"

# Минимальный порог размера ELF, чтобы не принять html-заглушку за бинарь.
_MIN_BIN_SIZE = 1_000_000


def _yaml_quote(value: str) -> str:
    """Заключить скаляр в двойные кавычки для YAML: URL содержит «:», «?», «&»."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_config(source_url: str) -> str:
    """go2rtc.yaml: один поток `decoy` из источника; API — только localhost, RTSP/WebRTC off.

    Пустой источник тоже валиден: поток объявлен без адреса (go2rtc это допускает),
    просто отдавать нечего, пока источник не задан.
    """
    source_line = (
        f"  {GO2RTC_STREAM_NAME}: {_yaml_quote(source_url)}" if str(source_url).strip() else f"  {GO2RTC_STREAM_NAME}:"
    )
    return (
        "api:\n"
        f'  listen: "{GO2RTC_API_HOST}:{GO2RTC_API_PORT}"\n'
        "rtsp:\n"
        '  listen: ""\n'
        "webrtc:\n"
        '  listen: ""\n'
        "srtp:\n"
        '  listen: ""\n'
        "log:\n"
        "  level: warn\n"
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
    """Поставить ffmpeg, если источник отдан ему (`ffmpeg:` в начале URL).

    Без бинаря go2rtc молча не отдаёт видео: ошибка ffmpeg-продюсера видна только в логе,
    а плеер стоит пустой. Поэтому отказ явный, с причиной в `on_error`.
    """
    if HOST.which(FFMPEG_PACKAGE):
        return True
    if not HOST.which("apt-get"):
        _fail(on_error, f"источник требует {FFMPEG_PACKAGE}, а на хосте нет ни его, ни apt-get")
        return False
    HOST.run(["apt-get", "update", "-qq"], timeout=300)
    result = HOST.run(["apt-get", "install", "-y", "-qq", FFMPEG_PACKAGE], text=True, timeout=300)
    if result.returncode != 0 or not HOST.which(FFMPEG_PACKAGE):
        _fail(on_error, f"{FFMPEG_PACKAGE} не установился: {str(result.stderr or '').strip()[:200]}")
        return False
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
    "FFMPEG_PACKAGE",
    "GO2RTC_BIN",
    "GO2RTC_CONFIG",
    "GO2RTC_REPO",
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
