"""Сторож медиа: поднимает поток по требованию и гасит его по простою.

Caddy не умеет запускать процессы, поэтому плейлист отдаётся не статикой, а через этот
маленький сервер на loopback. Он же — единственное место, где видно, что кто-то смотрит:
обращение к плейлисту продлевает потоку жизнь, тишина его гасит. Так поток не тянет
источник круглосуточно и не зависит от того, есть ли сейчас подключение к туннелю.

Сегменты через сторож не идут: это мегабайты неизменяемых файлов, их раздаёт Caddy
статикой. Сторож обслуживает только плейлист — он крошечный, запрашивается постоянно и
поэтому служит естественным пульсом зрителя.
"""

from __future__ import annotations

import contextlib
import math
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hydra.contracts.vless_cdn import (
    GATE_HOST,
    GATE_PORT,
    STREAM_HLS_TIME_DEFAULT,
    STREAM_IDLE_TIMEOUT_DEFAULT,
    STREAM_LIST_SIZE_DEFAULT,
    as_int,
)
from hydra.core import systemd, vless_cdn_stream
from hydra.core.sni_router_http import PLAYLIST_CACHE_CONTROL, PLAYLIST_CONTENT_TYPE

GATE_UNIT_NAME = "hydra-vless-cdn-media"
GATE_UNIT_SERVICE = f"{GATE_UNIT_NAME}.service"

# Сколько записей должно быть в плейлисте, чтобы отдавать его зрителю. Одной достаточно:
# hls.js начнёт играть и дождётся следующих. Ждать три записи — это лишние секунды
# пустого экрана на каждом заходе.
MIN_SEGMENTS = 1
# Плейлист считается свежим, пока он моложе нескольких длительностей сегмента: за это
# время ffmpeg обязан переписать его, иначе поток стоит.
FRESHNESS_FACTOR = 3
# Сколько ждать готового плейлиста на холодном старте: ffmpeg поднимается, тянет источник
# и режет первый сегмент по кейфрейму — это секунды, а не мгновение.
WAIT_SECONDS = 25.0
WAIT_STEP_SECONDS = 0.25
IDLE_CHECK_SECONDS = 5.0
# Дольше этого не ждём между проверками активности юнита: systemctl — это fork.
ACTIVITY_CACHE_SECONDS = 2.0


def _now() -> float:
    return time.time()


def playlist_is_playable(text: str, *, min_segments: int = MIN_SEGMENTS) -> bool:
    """Есть ли в плейлисте хоть что-то для проигрывания.

    Заголовок `#EXTM3U` ничего не доказывает: пустой плейлист — ровно то, что ffmpeg
    пишет в первые секунды после старта, и отдать его зрителю значит показать пустой плеер.
    """
    if "#EXTM3U" not in text:
        return False
    return text.count("#EXTINF") >= min_segments


def playlist_is_fresh(age: float | None, *, hls_time: int, factor: int = FRESHNESS_FACTOR) -> bool:
    """Переписывал ли ffmpeg плейлист недавно. `None` — файла нет вовсе."""
    if age is None:
        return False
    return age <= max(1.0, hls_time * factor)


class Gate:
    """Состояние сторожа: когда последний раз смотрели и когда пора гасить поток."""

    def __init__(
        self,
        *,
        idle_timeout: int = STREAM_IDLE_TIMEOUT_DEFAULT,
        hls_time: int = STREAM_HLS_TIME_DEFAULT,
        min_segments: int = MIN_SEGMENTS,
        wait_seconds: float = WAIT_SECONDS,
        clock: Callable[[], float] = _now,
        playlist_path: Path | None = None,
        age: Callable[[], float | None] | None = None,
        is_active: Callable[[], bool] = vless_cdn_stream.is_active,
        start: Callable[[], bool] = vless_cdn_stream.start,
        stop: Callable[[], bool] = vless_cdn_stream.stop,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.idle_timeout = as_int(idle_timeout)
        self.hls_time = max(1, as_int(hls_time))
        self.min_segments = max(1, as_int(min_segments))
        self.wait_seconds = wait_seconds
        self._clock = clock
        self._playlist_path = playlist_path or vless_cdn_stream.PLAYLIST_PATH
        self._age = age or self._default_age
        self._is_active = is_active
        self._start = start
        self._stop = stop
        self._sleep = sleep
        self._last_request = clock()
        # -inf, а не 0.0: первая же проверка активности обязана случиться, иначе холодный
        # старт пропустит подъём потока, если часы близки к нулю.
        self._last_check = -math.inf
        self._lock = threading.Lock()

    def touch(self) -> None:
        """Отметить зрителя: продлевает потоку жизнь."""
        with self._lock:
            self._last_request = self._clock()

    def idle_for(self) -> float:
        with self._lock:
            return self._clock() - self._last_request

    def should_stop(self) -> bool:
        """Пора ли гасить поток. `idle_timeout` = 0 — не гасим никогда."""
        if self.idle_timeout <= 0:
            return False
        return self.idle_for() >= self.idle_timeout

    def _default_age(self) -> float | None:
        """Возраст плейлиста по часам сервера. Инжектируется: тесты не ходят в файловую систему."""
        try:
            return max(0.0, self._clock() - self._playlist_path.stat().st_mtime)
        except OSError:
            return None

    def read_playlist(self) -> str | None:
        try:
            return self._playlist_path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _ready(self) -> bytes | None:
        """Готовый плейлист или None. Свежесть важнее содержимого: старый плейлист
        выглядит валидным, но сегменты в нём уже удалены."""
        text = self.read_playlist()
        if text is None:
            return None
        if not playlist_is_fresh(self._age(), hls_time=self.hls_time):
            return None
        if not playlist_is_playable(text, min_segments=self.min_segments):
            return None
        return text.encode("utf-8")

    def _ensure_running(self) -> None:
        """Поднять поток, если он спит. В установившемся режиме systemctl не зовём."""
        now = self._clock()
        if now - self._last_check < ACTIVITY_CACHE_SECONDS:
            return
        self._last_check = now
        if not self._is_active():
            self._start()

    def playlist(self) -> bytes | None:
        """Плейлист для зрителя: поднять поток, дождаться сегментов, отдать файл.

        Ждём только на холодном старте. В установившемся режиме файл уже готов, и ответ
        отдаётся без единого вызова systemctl.
        """
        self.touch()
        ready = self._ready()
        if ready is not None:
            return ready
        self._ensure_running()
        deadline = self._clock() + self.wait_seconds
        while self._clock() < deadline:
            self._sleep(WAIT_STEP_SECONDS)
            ready = self._ready()
            if ready is not None:
                return ready
            # Поток мог упасть, пока мы ждали: RestartSec у него 3 с, но и его надо толкать.
            self._last_check = 0.0
            self._ensure_running()
        return None

    def watchdog_once(self) -> bool:
        """Одна проверка простоя: True, если поток погашен."""
        if not self.should_stop():
            return False
        if not self._is_active():
            return False
        self._stop()
        return True


class _Handler(BaseHTTPRequestHandler):
    """Отдаёт плейлист. Всё остальное — забота Caddy, он сюда не ходит."""

    protocol_version = "HTTP/1.1"
    server_version = "hydra-media"
    sys_version = ""
    gate: Gate

    def do_GET(self) -> None:  # noqa: N802 — имя задано базовым классом
        body = self.gate.playlist()
        if body is None:
            # 503, а не пустой плейлист: Caddy на 5xx отдаёт статику, и медиа-путь не
            # выглядит голой ошибкой.
            self.send_error(503, "stream not ready")
            return
        self.send_response(200)
        self.send_header("Content-Type", PLAYLIST_CONTENT_TYPE)
        self.send_header("Cache-Control", PLAYLIST_CACHE_CONTROL)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, *args: object) -> None:
        """Молча: журнал нужен для ошибок, а не для каждого запроса плейлиста."""


def _watchdog(gate: Gate, *, stop: threading.Event) -> None:
    while not stop.wait(IDLE_CHECK_SECONDS):
        with contextlib.suppress(Exception):
            gate.watchdog_once()


def serve(
    gate: Gate,
    *,
    host: str = GATE_HOST,
    port: int = GATE_PORT,
    ready: threading.Event | None = None,
) -> None:
    """Поднять сторож и стеречь простой до остановки процесса."""
    handler = type("_BoundHandler", (_Handler,), {"gate": gate})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    stop = threading.Event()
    thread = threading.Thread(target=_watchdog, args=(gate,), kwargs={"stop": stop}, daemon=True)
    thread.start()
    if ready is not None:
        ready.set()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()


def render_unit(
    *,
    idle_timeout: int,
    hls_time: int,
    list_size: int,
    root: Path | None = None,
    interpreter: Path | None = None,
    port: int = GATE_PORT,
) -> str:
    """Юнит сторожа. Настройки вкомпонованы в команду: смена настройки — переустановка.

    Так сторож не читает состояние и не знает про его схему: всё, что ему нужно, он
    получает аргументами, и подделать это на ходу нельзя.
    """
    from hydra.core.install_layout import project_root as _project_root
    from hydra.core.install_layout import python_executable

    project = (root or _project_root()).as_posix()
    python = (interpreter or python_executable(project)).as_posix()
    return f"""[Unit]
Description=HYDRA VLESS CDN decoy media gate (on-demand stream)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={project}
Environment=PYTHONPATH={project}
ExecStart={python} -m hydra.entrypoints.vless_cdn_media --port {port} --idle-timeout {idle_timeout} --hls-time {hls_time} --list-size {list_size}
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def install(
    *,
    idle_timeout: int,
    hls_time: int,
    list_size: int,
    on_error: Callable[[str], None] | None = None,
) -> bool:
    """Поставить сторож и включить его: он должен ждать зрителя с загрузки."""
    unit = render_unit(idle_timeout=idle_timeout, hls_time=hls_time, list_size=list_size)
    if not systemd.install_service(GATE_UNIT_NAME, unit):
        if on_error is not None:
            on_error("не удалось установить юнит сторожа медиа")
        return False
    return systemd.restart(GATE_UNIT_SERVICE)


def remove() -> bool:
    """Снять сторож. Поток при этом тоже гасим: без сторожа его никто не поднимет."""
    vless_cdn_stream.stop()
    return systemd.remove_unit(GATE_UNIT_NAME)


def is_active() -> bool:
    return systemd.is_active(GATE_UNIT_SERVICE)


__all__ = [
    "FRESHNESS_FACTOR",
    "GATE_UNIT_NAME",
    "GATE_UNIT_SERVICE",
    "IDLE_CHECK_SECONDS",
    "MIN_SEGMENTS",
    "Gate",
    "install",
    "is_active",
    "playlist_is_fresh",
    "playlist_is_playable",
    "remove",
    "render_unit",
    "serve",
]
