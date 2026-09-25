"""Сторож медиа: готовность плейлиста, простой и отдача зрителю."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hydra.core import vless_cdn_media as media

PLAYLIST = "#EXTM3U\n#EXT-X-TARGETDURATION:3\n#EXTINF:3.001,\nseg/s1.ts\n"


class _Clock:
    """Часы, которые двигает тест: сторож не должен зависеть от реального времени."""

    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _gate(**overrides) -> media.Gate:
    options: dict[str, object] = {
        "idle_timeout": 120,
        "hls_time": 2,
        "clock": _Clock(0.0),
        "age": lambda: 0.0,
        "playlist_path": Path("/nonexistent/playlist.m3u8"),
        "is_active": lambda: True,
        "start": lambda: True,
        "stop": lambda: True,
        "sleep": lambda _seconds: None,
    }
    options.update(overrides)
    return media.Gate(**options)  # type: ignore[arg-type]


# ── Готовность плейлиста ───────────────────────────────────────────────────────


def test_header_alone_is_not_a_playable_playlist():
    # Пустой плейлист — ровно то, что ffmpeg пишет в первые секунды после старта. Отдать
    # его зрителю значит показать пустой плеер.
    assert media.playlist_is_playable("#EXTM3U\n#EXT-X-TARGETDURATION:3\n") is False
    assert media.playlist_is_playable(PLAYLIST) is True


@pytest.mark.parametrize(("age", "expected"), [(None, False), (100.0, False), (1.0, True)])
def test_freshness_follows_the_segment_length(age, expected):
    # Старый плейлист выглядит валидным, но сегменты в нём уже удалены.
    assert media.playlist_is_fresh(age, hls_time=2) is expected


# ── Простой ────────────────────────────────────────────────────────────────────


def test_zero_idle_timeout_means_never_stop():
    clock = _Clock()
    gate = _gate(idle_timeout=0, clock=clock)
    clock.value = 10_000.0
    assert gate.should_stop() is False


def test_gate_stops_only_after_the_idle_timeout():
    clock = _Clock()
    gate = _gate(idle_timeout=60, clock=clock)
    clock.value = 30.0
    assert gate.should_stop() is False
    clock.value = 61.0
    assert gate.should_stop() is True


def test_watchdog_leaves_a_watched_stream_alone():
    clock = _Clock()
    stop = MagicMock(return_value=True)
    gate = _gate(idle_timeout=60, clock=clock, stop=stop)
    clock.value = 5.0
    assert gate.watchdog_once() is False
    stop.assert_not_called()


def test_watchdog_stops_an_idle_stream():
    clock = _Clock()
    stop = MagicMock(return_value=True)
    gate = _gate(idle_timeout=60, clock=clock, stop=stop)
    clock.value = 120.0
    assert gate.watchdog_once() is True
    stop.assert_called_once()


def test_watchdog_does_not_touch_a_sleeping_stream():
    clock = _Clock()
    stop = MagicMock(return_value=True)
    gate = _gate(idle_timeout=60, clock=clock, stop=stop, is_active=lambda: False)
    clock.value = 120.0
    assert gate.watchdog_once() is False
    stop.assert_not_called()


# ── Отдача ─────────────────────────────────────────────────────────────────────


def test_ready_playlist_is_served_without_touching_systemd(tmp_path):
    # В установившемся режиме плейлист запрашивают каждую секунду: systemctl на каждый
    # запрос — это fork на каждый запрос.
    playlist = tmp_path / "playlist.m3u8"
    playlist.write_text(PLAYLIST, encoding="utf-8")
    active = MagicMock(return_value=True)
    gate = _gate(playlist_path=playlist, is_active=active)

    assert gate.playlist() == PLAYLIST.encode()
    active.assert_not_called()


def test_cold_start_raises_the_stream_and_waits_for_the_first_segment(tmp_path):
    playlist = tmp_path / "playlist.m3u8"
    started: list[bool] = []
    ages = [None, None]

    def age():
        return ages.pop(0) if ages else 0.0

    def sleep(_seconds):
        playlist.write_text(PLAYLIST, encoding="utf-8")

    gate = _gate(
        playlist_path=playlist,
        age=age,
        is_active=lambda: False,
        start=lambda: started.append(True) or True,
        sleep=sleep,
    )

    assert gate.playlist() == PLAYLIST.encode()
    assert started, "холодный старт обязан поднять поток"


def test_cold_start_gives_up_when_the_stream_never_produces():
    # None → сторож отдаёт 503, и Caddy подставляет статику вместо голой ошибки.
    clock = _Clock()

    def sleep(_seconds):
        clock.value += 5.0

    gate = _gate(clock=clock, is_active=lambda: False, sleep=sleep)

    assert gate.playlist() is None


# ── Юнит ───────────────────────────────────────────────────────────────────────


def test_gate_unit_starts_at_boot_and_carries_the_settings():
    unit = media.render_unit(
        idle_timeout=90,
        hls_time=3,
        list_size=12,
        root=Path("/opt/hydra"),
        interpreter=Path("/opt/hydra/.venv/bin/python"),
    )

    # Сторож, в отличие от потока, обязан ждать зрителя с загрузки: без него поток никто
    # не поднимет.
    assert "WantedBy=multi-user.target" in unit
    assert "hydra.entrypoints.vless_cdn_media" in unit
    assert "--idle-timeout 90" in unit
    assert "--hls-time 3" in unit
    assert "--list-size 12" in unit
