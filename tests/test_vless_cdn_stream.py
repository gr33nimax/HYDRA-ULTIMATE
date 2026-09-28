"""Поток прикрытия: команда ffmpeg, юнит и жизненный цикл."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hydra.core import vless_cdn_stream as stream

SOURCE = "https://cam.example/live/index.m3u8"


def _command(*, hls_time: int = 2, list_size: int = 10) -> list[str]:
    return stream.build_command(SOURCE, hls_time=hls_time, list_size=list_size)


# ── Команда ffmpeg ─────────────────────────────────────────────────────────────


def test_command_is_a_remux_with_real_segment_durations():
    command = _command()

    assert command[command.index("-c") + 1] == "copy", "ремукс, а не перекодирование"
    assert command[command.index("-hls_segment_type") + 1] == "mpegts"
    assert command[command.index("-hls_flags") + 1] == stream.HLS_FLAGS


def test_command_numbers_segments_from_epoch():
    # Иначе при перезапуске ffmpeg последовательность сбросится, а имена сегментов совпадут
    # с прежними — и плеер возьмёт из кеша чужое содержимое.
    command = _command()
    assert command[command.index("-hls_start_number_source") + 1] == "epoch"


def test_segment_urls_are_relative_to_the_playlist():
    command = _command()
    assert command[command.index("-hls_base_url") + 1] == "seg/"
    assert stream.segment_base_url() == "seg/"


def test_command_never_reads_stdin():
    # Без -nostdin ffmpeg читает команды со stdin и съедает чужой ввод: под systemd это
    # ломает запуск, а при ручной проверке — половину скрипта.
    assert "-nostdin" in _command()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("https://cam.example/live/index.m3u8", "-reconnect"),
        ("rtsp://cam.example:554/live", "-rtsp_transport"),
    ],
)
def test_input_flags_follow_the_source_form(source, expected):
    # HTTP-источник переподключается; RTSP идёт по TCP и с таймаутом: UDP за NAT теряется,
    # а без таймаута процесс висит на мёртвой камере.
    command = stream.build_command(source, hls_time=2, list_size=10)
    assert expected in command


def test_legacy_ffmpeg_prefix_is_stripped():
    # Прежние инсталляции хранят источник с префиксом go2rtc: он больше ничего не значит,
    # но и мешать не должен.
    command = stream.build_command("ffmpeg:" + SOURCE, hls_time=2, list_size=10)
    assert command[command.index("-i") + 1] == SOURCE


def test_segment_window_is_bounded():
    command = _command(hls_time=3, list_size=7)
    assert command[command.index("-hls_time") + 1] == "3"
    assert command[command.index("-hls_list_size") + 1] == "7"


# ── Юнит ───────────────────────────────────────────────────────────────────────


def test_unit_is_on_demand_and_restarts_on_failure():
    unit = stream.render_unit(_command())

    assert "[Install]" not in unit, "поток поднимается по требованию, а не на загрузке"
    assert "Restart=always" in unit, "упавший поток должен подниматься сам"
    assert "ExecStartPre=" in unit, "осиротевшие сегменты прошлых запусков надо сметать"


def test_unit_may_write_only_the_window_directory():
    unit = stream.render_unit(_command(), media_dir=Path("/var/www/x/api/media"))

    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/www/x/api/media" in unit


def test_unit_quotes_arguments_with_spaces():
    # systemd разбирает ExecStart сам: пробел в URL склеил бы два аргумента.
    command = ["/usr/local/bin/ffmpeg", "-i", "https://h/x.m3u8?a=1 b=2"]
    assert '"https://h/x.m3u8?a=1 b=2"' in stream.render_unit(command)


def test_unit_escapes_percent_in_segment_names():
    # `%` в ExecStart — спецификатор systemd (`%d` — каталог credentials). Незаэкранированный
    # `s%d.ts` делает юнит `bad-setting`, и служба не стартует вовсе: именно так декой не
    # работал после раскатки, а в журнале не было ни строки от ffmpeg.
    unit = stream.render_unit(_command())

    assert "s%%d.ts" in unit
    assert "s%d.ts" not in unit


def test_unit_escapes_percent_in_a_source_url():
    # URL с процентным кодированием — обычное дело, и он тоже идёт в ExecStart.
    command = stream.build_command("https://cam.example/a%20b/index.m3u8", hls_time=2, list_size=10)

    assert "a%%20b" in stream.render_unit(command)


# ── Жизненный цикл ─────────────────────────────────────────────────────────────


def test_install_fails_closed_without_ffmpeg(monkeypatch):
    monkeypatch.setattr(stream, "ensure_ffmpeg", lambda **_k: False)
    install = MagicMock(return_value=True)
    monkeypatch.setattr(stream.systemd, "install_service", install)

    assert stream.install(SOURCE, hls_time=2, list_size=10) is False
    install.assert_not_called()


def test_install_removes_the_legacy_relay_and_leaves_the_unit_disabled(monkeypatch):
    monkeypatch.setattr(stream, "ensure_ffmpeg", lambda **_k: True)
    monkeypatch.setattr(stream, "ensure_directories", lambda **_k: None)
    removed: list[str] = []
    monkeypatch.setattr(stream.systemd, "remove_unit", lambda name: removed.append(name) or True)
    captured: dict[str, object] = {}

    def fake_install(name, content, *, enable=True):
        captured.update(name=name, content=content, enable=enable)
        return True

    monkeypatch.setattr(stream.systemd, "install_service", fake_install)

    assert stream.install(SOURCE, hls_time=2, list_size=10) is True
    assert removed == list(stream.LEGACY_UNITS), "прежняя ретрансляция должна быть снята"
    assert captured["enable"] is False, "поток не должен стартовать на загрузке"
    assert "ExecStart=" in str(captured["content"])


def test_apply_source_does_not_wake_a_sleeping_stream(monkeypatch):
    monkeypatch.setattr(stream, "install", lambda *_a, **_k: True)
    monkeypatch.setattr(stream.systemd, "is_active", lambda _svc: False)
    restart = MagicMock(return_value=True)
    monkeypatch.setattr(stream.systemd, "restart", restart)

    assert stream.apply_source(SOURCE, hls_time=2, list_size=10) is True
    restart.assert_not_called()


def test_ensure_ffmpeg_refuses_an_unknown_architecture(monkeypatch, tmp_path):
    monkeypatch.setattr(stream, "FFMPEG_BIN", tmp_path / "ffmpeg")
    monkeypatch.setattr("hydra.utils.net.detect_arch", lambda: "riscv64")

    errors: list[str] = []
    assert stream.ensure_ffmpeg(on_error=errors.append) is False
    assert errors and "riscv64" in errors[0]
