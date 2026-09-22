"""Живой медиапоток прикрытия: непрерывный ffmpeg и сторож источника/синтетики.

Модуль собирает systemd-сервис, который держит HLS-поток заглушки, следит за зависимостью
ffmpeg и запускает процесс только через host-слой (`HOST.popen`): прямой `subprocess` в
production-коде разрешён лишь в `hydra/utils/commands.py`. Резолв YouTube-потока проходит
обязательную проверку на SSRF — URL, который вернул yt-dlp, доверия не заслуживает.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import shutil
from typing import Any

from hydra.contracts.vless_cdn import (
    DECOY_ROOT,
    MEDIA_SOURCE_YOUTUBE,
    PROTOCOL_NAME,
    classify_media_source,
)
from hydra.core import systemd
from hydra.core.host import HOST
from hydra.core.install_layout import project_root as _project_root
from hydra.core.install_layout import python_executable
from hydra.core.state_models import AppState
from hydra.core.vless_cdn_stream import (
    FFMPEG,
    YTDLP,
    StreamPlan,
    media_directory,
    stream_plan,
    ytdlp_command,
)

STREAM_UNIT_NAME = "hydra-vless-cdn-stream"
STREAM_UNIT_SERVICE = f"{STREAM_UNIT_NAME}.service"

FFMPEG_PACKAGE = "ffmpeg"
APT_UPDATE_TIMEOUT = 120.0
APT_INSTALL_TIMEOUT = 300.0
YTDLP_TIMEOUT = 60.0

# Пауза перед перезапуском упавшего ffmpeg и через сколько синтетических прогонов снова
# пробовать реальный источник: сторож не должен ни крутиться в цикле, ни навсегда забыть
# камеру после одной сетевой икоты.
RESTART_DELAY_SECONDS = 3.0
RETRY_SOURCE_AFTER = 6


def _returncode(result: object) -> int:
    value = getattr(result, "returncode", 1)
    return value if isinstance(value, int) else 1


def ensure_ffmpeg(*, host: Any = HOST, package: str = FFMPEG_PACKAGE) -> bool:
    """Поставить ffmpeg, если его нет: без него поток не собрать, а пустой стрим хуже отказа."""
    if host.which(FFMPEG):
        return True
    update = host.run(["apt-get", "update", "-qq"], timeout=APT_UPDATE_TIMEOUT)
    install = host.run(["apt-get", "install", "-y", "-qq", package], timeout=APT_INSTALL_TIMEOUT)
    if _returncode(update) != 0 or _returncode(install) != 0:
        return False
    return host.which(FFMPEG) is not None


def resolve_youtube_url(
    watch_url: object,
    *,
    host: Any = HOST,
    timeout: float = YTDLP_TIMEOUT,
) -> str:
    """Прямой адрес потока для YouTube-страницы: первый непустой URL из вывода yt-dlp.

    Возвращённый адрес потом ещё раз проверяется контрактом (SSRF) в `stream_plan`: yt-dlp —
    внешний инструмент, и доверять его ответу без проверки нельзя.
    """
    if host.which(YTDLP) is None:
        return ""
    result = host.run(ytdlp_command(watch_url), timeout=timeout, text=True)
    if _returncode(result) != 0:
        return ""
    for line in str(getattr(result, "stdout", "") or "").splitlines():
        candidate = line.strip()
        if candidate.startswith(("http://", "https://", "rtsp://")):
            return candidate
    return ""


def run_ffmpeg(plan: StreamPlan, *, host: Any = HOST) -> int:
    """Запустить ffmpeg по готовому argv и дождаться выхода; код — как есть."""
    process = host.popen(plan.command)
    return int(process.wait())


def run_supervisor(
    *,
    source_url: object,
    output_dir: str | Path,
    region: str = "",
    cam_id: str = "",
    seed: str = "",
    run: Callable[[StreamPlan], int],
    youtube_url: Callable[[str], str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
    sleep: Callable[[float], None],
    log: Callable[[str], None],
    max_attempts: int | None = None,
    restart_delay: float = RESTART_DELAY_SECONDS,
    retry_source_after: int = RETRY_SOURCE_AFTER,
) -> int:
    """Держать живой HLS: реальный источник, пока он жив; синтетика — когда он упал.

    Сторож помнит серию провалов: упавший источник уводит на синтетику, но через
    `retry_source_after` прогонов камера пробуется снова. `run`/`sleep`/`log`/`youtube_url`
    инжектируемы — тесты не запускают процесс и не спят. Синтетика недостижима только если
    она сама падает, чего быть не должно (внешних файлов у неё нет).
    """
    synthetic_streak = 0
    attempts = 0
    while max_attempts is None or attempts < max_attempts:
        attempts += 1
        use_source = synthetic_streak == 0 or synthetic_streak >= retry_source_after
        url = source_url if use_source else ""
        resolved = _resolve_youtube(url, youtube_url)
        plan = stream_plan(
            url,
            output_dir=output_dir,
            region=region,
            cam_id=cam_id,
            seed=seed,
            youtube_stream_url=resolved or None,
            which=which,
        )
        log(f"stream: kind={plan.kind} synthetic={plan.synthetic} reason={plan.reason}")
        code = int(run(plan))
        if plan.synthetic:
            synthetic_streak = 1 if synthetic_streak == 0 else synthetic_streak + 1
        elif code == 0:
            synthetic_streak = 0
        else:
            synthetic_streak = 1
        if code != 0 and restart_delay:
            sleep(restart_delay)
    return 0


def _resolve_youtube(url: object, youtube_url: Callable[[str], str] | None) -> str:
    if not url or youtube_url is None:
        return ""
    try:
        kind = classify_media_source(url)
    except ValueError:
        return ""
    if kind != MEDIA_SOURCE_YOUTUBE:
        return ""
    return str(youtube_url(str(url)) or "")


def run_for_state(
    state: AppState,
    *,
    output_dir: str | Path | None = None,
    run: Callable[[StreamPlan], int] = run_ffmpeg,
    youtube_url: Callable[[str], str] | None = resolve_youtube_url,
    sleep: Callable[[float], None] | None = None,
    log: Callable[[str], None] | None = None,
    max_attempts: int | None = None,
) -> int:
    """Собрать параметры потока из состояния и запустить сторожа."""
    import time

    protocol = state.protocols.get(PROTOCOL_NAME)
    config = protocol.config if protocol else {}
    directory = Path(output_dir) if output_dir is not None else media_directory(DECOY_ROOT)
    directory.mkdir(parents=True, exist_ok=True)
    region = str(config.get("region_city", "") or config.get("region_country_name", "") or "").strip()
    seed = str(config.get("origin_host", "") or config.get("cdn_domain", "") or "").strip()
    return run_supervisor(
        source_url=str(config.get("cam_source_url", "") or ""),
        output_dir=directory,
        region=region,
        seed=seed,
        run=run,
        youtube_url=youtube_url,
        sleep=sleep or time.sleep,
        log=log or (lambda _message: None),
        max_attempts=max_attempts,
    )


def stream_units(
    root: Path | None = None,
    interpreter: Path | None = None,
) -> str:
    """Юнит сервиса — той же формы, что остальные фоновые задачи HYDRA."""
    project = root or _project_root()
    python = interpreter or python_executable(project)
    return f"""[Unit]
Description=HYDRA VLESS CDN decoy live stream
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory={project}
Environment=PYTHONPATH={project}
ExecStart={python} -m hydra.entrypoints.vless_cdn_stream
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
"""


def install_stream_service(root: Path | None = None) -> bool:
    """Поставить ffmpeg, включить и запустить сервис живого потока."""
    if not ensure_ffmpeg():
        return False
    if not systemd.install_service(STREAM_UNIT_NAME, stream_units(root)):
        return False
    return systemd.start(STREAM_UNIT_SERVICE)


def remove_stream_service() -> bool:
    return systemd.remove_unit(STREAM_UNIT_NAME)


__all__ = [
    "RETRY_SOURCE_AFTER",
    "STREAM_UNIT_NAME",
    "STREAM_UNIT_SERVICE",
    "ensure_ffmpeg",
    "install_stream_service",
    "remove_stream_service",
    "resolve_youtube_url",
    "run_ffmpeg",
    "run_for_state",
    "run_supervisor",
    "stream_units",
]
