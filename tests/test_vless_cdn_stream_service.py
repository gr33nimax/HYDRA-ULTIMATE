"""TSK-03: сервис живого потока — зависимость ffmpeg, сторож источника и systemd-юнит."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.contracts.vless_cdn import PROTOCOL_NAME
from hydra.services import vless_cdn_stream as stream

PUBLIC_HLS = "https://1.1.1.1/live/stream.m3u8"


@dataclass
class _Result:
    returncode: int = 0
    stdout: str = ""


class _AptHost:
    """Хост для ensure_ffmpeg: помнит команды и «появляет» ffmpeg после установки."""

    def __init__(self, *, present: bool = False, install_ok: bool = True) -> None:
        self.has_ffmpeg = present
        self.install_ok = install_ok
        self.commands: list[list[str]] = []

    def which(self, name: str) -> str | None:
        return "/usr/bin/ffmpeg" if name == "ffmpeg" and self.has_ffmpeg else None

    def run(self, args, **_kwargs) -> _Result:
        argv = [str(item) for item in args]
        self.commands.append(argv)
        if argv[:2] == ["apt-get", "install"] and self.install_ok:
            self.has_ffmpeg = True
        return _Result(0 if self.install_ok else 1, "")


class _YtdlpHost:
    def __init__(self, *, present: bool = True, stdout: str = "", returncode: int = 0) -> None:
        self.present = present
        self.stdout = stdout
        self.returncode = returncode
        self.commands: list[list[str]] = []

    def which(self, name: str) -> str | None:
        return "/usr/bin/yt-dlp" if name == "yt-dlp" and self.present else None

    def run(self, args, **_kwargs) -> _Result:
        self.commands.append([str(item) for item in args])
        return _Result(self.returncode, self.stdout)


# ── ffmpeg как bootstrap-зависимость ─────────────────────────────────────────────


def test_ffmpeg_present_needs_no_package_manager():
    host = _AptHost(present=True)

    assert stream.ensure_ffmpeg(host=host) is True
    assert host.commands == [], "уже установленный ffmpeg не трогаем"


def test_ffmpeg_is_installed_when_missing():
    host = _AptHost(present=False)

    assert stream.ensure_ffmpeg(host=host) is True
    assert ["apt-get", "update", "-qq"] in host.commands
    assert any(argv[:2] == ["apt-get", "install"] and "ffmpeg" in argv for argv in host.commands)


def test_ffmpeg_install_failure_is_reported_not_ignored():
    host = _AptHost(present=False, install_ok=False)

    assert stream.ensure_ffmpeg(host=host) is False


class _PipHost:
    """yt_dlp модуль отсутствует до install, потом появляется (pip успешен)."""

    def __init__(self, *, install_ok: bool = True) -> None:
        self.install_ok = install_ok
        self.commands: list[list[str]] = []
        self._installed = False

    def run(self, args, **_kwargs) -> _Result:
        argv = [str(item) for item in args]
        self.commands.append(argv)
        if argv[1:3] == ["-m", "yt_dlp"] and argv[3:4] == ["--version"]:
            return _Result(0 if self._installed else 1, "")
        if argv[1:4] == ["-m", "pip", "install"]:
            self._installed = self.install_ok
            return _Result(0 if self.install_ok else 1, "")
        return _Result(0, "")


def test_ytdlp_present_needs_no_pip():
    host = _PipHost()
    host._installed = True

    assert stream.ensure_ytdlp(host=host, python="/venv/python") is True
    assert all(argv[1:4] != ["-m", "pip", "install"] for argv in host.commands), "уже есть — не ставим"


def test_ytdlp_is_installed_when_missing():
    host = _PipHost(install_ok=True)

    assert stream.ensure_ytdlp(host=host, python="/venv/python") is True
    assert any(argv[1:4] == ["-m", "pip", "install"] and "yt-dlp" in argv for argv in host.commands)


def test_ytdlp_install_failure_is_not_fatal_returns_false():
    host = _PipHost(install_ok=False)

    assert stream.ensure_ytdlp(host=host, python="/venv/python") is False


# ── Резолв YouTube-потока (и проверка на SSRF ниже — в stream_plan) ──────────────


def test_youtube_without_ytdlp_resolves_nothing():
    # yt-dlp вызывается как `python -m yt_dlp`; его отсутствие — ненулевой код (модуль не найден).
    assert stream.resolve_youtube_url("https://youtu.be/abc", host=_YtdlpHost(returncode=1)) == ""


def test_youtube_url_is_taken_from_the_first_url_line():
    host = _YtdlpHost(stdout="WARNING: noisy\nhttps://video.example/stream.m3u8\n")

    assert (
        stream.resolve_youtube_url("https://youtu.be/abc", host=host, python="/venv/python")
        == "https://video.example/stream.m3u8"
    )
    # Зовётся через `python -m yt_dlp`, а не консольный скрипт — PATH systemd-юнита не важен.
    assert host.commands[0][:3] == ["/venv/python", "-m", "yt_dlp"]


def test_youtube_failure_resolves_nothing():
    host = _YtdlpHost(stdout="https://video.example/x.m3u8", returncode=1)

    assert stream.resolve_youtube_url("https://youtu.be/abc", host=host) == ""


# ── Юнит сервиса ─────────────────────────────────────────────────────────────────


def test_stream_unit_runs_the_entrypoint_and_restarts():
    root = Path("/opt/hydra")
    interpreter = root / ".venv" / "bin" / "python"

    unit = stream.stream_units(root, interpreter)

    assert f"ExecStart={interpreter} -m hydra.entrypoints.vless_cdn_stream" in unit
    assert f"WorkingDirectory={root}" in unit
    assert f"PYTHONPATH={root}" in unit
    assert "Type=simple" in unit
    assert "Restart=always" in unit
    assert "WantedBy=multi-user.target" in unit


def test_install_stream_service_needs_ffmpeg_first(monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(stream, "ensure_ffmpeg", lambda **_kwargs: False)
    monkeypatch.setattr(stream.systemd, "install_service", lambda *_args: called.append("unit") or True)

    assert stream.install_stream_service() is False
    assert called == [], "без ffmpeg не пишем юнит"


def test_install_stream_service_enables_and_starts(monkeypatch):
    seen: dict[str, object] = {}

    def fake_install_service(name: str, _content: str) -> bool:
        seen["name"] = name
        return True

    def fake_start(unit: str) -> bool:
        seen["start"] = unit
        return True

    monkeypatch.setattr(stream, "ensure_ffmpeg", lambda **_kwargs: True)
    monkeypatch.setattr(stream.systemd, "install_service", fake_install_service)
    monkeypatch.setattr(stream.systemd, "start", fake_start)

    assert stream.install_stream_service() is True
    assert seen["name"] == stream.STREAM_UNIT_NAME
    assert seen["start"] == stream.STREAM_UNIT_SERVICE


def test_remove_stream_service_delegates(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(stream.systemd, "remove_unit", lambda name: seen.append(name) or True)

    assert stream.remove_stream_service() is True
    assert seen == [stream.STREAM_UNIT_NAME]


# ── Сторож источника и синтетики ─────────────────────────────────────────────────


def _supervisor(*codes, source=PUBLIC_HLS, retry=2, attempts=None, which=None, youtube_url=None):
    seen: list[str] = []
    sleeps: list[float] = []
    queue = list(codes)

    def run(plan):
        seen.append(plan.kind)
        return queue.pop(0) if queue else 0

    stream.run_supervisor(
        source_url=source,
        output_dir="/tmp/out",
        seed="host.example",
        run=run,
        youtube_url=youtube_url,
        which=which or (lambda _name: None),
        sleep=lambda seconds: sleeps.append(seconds),
        log=lambda _message: None,
        max_attempts=attempts if attempts is not None else len(codes),
        retry_source_after=retry,
    )
    return seen, sleeps


def test_supervisor_keeps_the_source_while_it_stays_up():
    seen, _ = _supervisor(0, 0, 0)
    assert seen == ["hls", "hls", "hls"]


def test_supervisor_switches_to_synthetic_when_the_source_dies():
    seen, sleeps = _supervisor(1, 0, 0, retry=10)
    assert seen[0] == "hls"
    assert seen[1] == "synthetic", "упавший источник уводит на синтетику"
    assert sleeps and sleeps[0] > 0, "перезапуск не крутится без паузы"


def test_supervisor_retries_the_source_after_the_synthetic_streak():
    seen, _ = _supervisor(1, 0, 0, retry=2)
    assert seen == ["hls", "synthetic", "hls"], "после серии синтетики камера пробуется снова"


def test_supervisor_with_no_source_stays_on_synthetic():
    seen, _ = _supervisor(0, 0, 0, source="")
    assert set(seen) == {"synthetic"}


def test_supervisor_feeds_the_resolved_youtube_url_to_the_plan():
    seen, _ = _supervisor(
        0,
        source="https://youtu.be/abc",
        which=lambda _name: "/usr/bin/yt-dlp",
        youtube_url=lambda _url: "https://1.1.1.1/stream.m3u8",
    )
    assert seen == ["youtube"]


# ── Сбор параметров из состояния ─────────────────────────────────────────────────


def test_run_for_state_reads_the_camera_and_region(tmp_path):
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(
        enabled=True,
        config={
            "cam_source_url": PUBLIC_HLS,
            "region_city": "Helsinki",
            "origin_host": "origin.example",
        },
    )
    seen: list[str] = []

    result = stream.run_for_state(
        state,
        output_dir=tmp_path,
        run=lambda plan: (seen.append(plan.kind), 0)[1],
        youtube_url=None,
        sleep=lambda _seconds: None,
        log=lambda _message: None,
        max_attempts=1,
    )

    assert result == 0
    assert seen == ["hls"]
    assert tmp_path.exists()
    # ffmpeg не создаёт каталог сегмента сам — без этого поток падает на seg/seg-00000.ts.
    assert (tmp_path / "seg").is_dir()


def test_run_for_state_without_a_camera_falls_back_to_synthetic(tmp_path):
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(enabled=True, config={})
    seen: list[str] = []

    stream.run_for_state(
        state,
        output_dir=tmp_path,
        run=lambda plan: (seen.append(plan.kind), 0)[1],
        youtube_url=None,
        sleep=lambda _seconds: None,
        log=lambda _message: None,
        max_attempts=1,
    )

    assert seen == ["synthetic"]
