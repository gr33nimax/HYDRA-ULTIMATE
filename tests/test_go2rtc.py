"""go2rtc-ретранслятор: конфиг, юнит и провижининг бинаря."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from hydra.core import go2rtc


def test_config_binds_api_to_localhost_and_disables_public_servers():
    text = go2rtc.render_config("rtsp://cam.example/live")

    assert 'listen: "127.0.0.1:1984"' in text, "API только на localhost"
    # RTSP/WebRTC/SRTP наружу торчать не должны — иначе открытый стриминг-сервер.
    assert text.count('listen: ""') == 3
    assert 'decoy: "rtsp://cam.example/live"' in text


def test_config_quotes_source_with_query_and_empty_is_valid():
    # URL с «?&:» обязан быть в кавычках, иначе YAML сломается.
    text = go2rtc.render_config("https://h/x.m3u8?a=1&b=2")
    assert 'decoy: "https://h/x.m3u8?a=1&b=2"' in text

    empty = go2rtc.render_config("")
    assert "decoy:" in empty and '""' not in empty.split("streams:")[1]


def test_config_escapes_quotes_in_source():
    text = go2rtc.render_config('rtsp://h/a"b')
    assert 'decoy: "rtsp://h/a\\"b"' in text


def test_unit_runs_the_pinned_binary_with_the_config(monkeypatch):
    captured: dict[str, str] = {}
    monkeypatch.setattr(go2rtc.systemd, "install_service", lambda name, content: captured.update(name=name, content=content) or True)
    monkeypatch.setattr(go2rtc.systemd, "start", lambda _svc: True)
    monkeypatch.setattr(go2rtc, "ensure_binary", lambda: True)
    monkeypatch.setattr(go2rtc, "write_config", lambda _src: None)

    assert go2rtc.install("rtsp://cam/live") is True
    assert captured["name"] == "hydra-go2rtc"
    assert str(go2rtc.GO2RTC_BIN) in captured["content"]
    assert str(go2rtc.GO2RTC_CONFIG) in captured["content"]


def test_install_fails_closed_without_binary(monkeypatch):
    monkeypatch.setattr(go2rtc, "ensure_binary", lambda: False)
    install = MagicMock(return_value=True)
    monkeypatch.setattr(go2rtc.systemd, "install_service", install)

    assert go2rtc.install("rtsp://cam/live") is False
    install.assert_not_called()


def test_apply_source_rewrites_config_and_restarts(monkeypatch, tmp_path):
    monkeypatch.setattr(go2rtc, "GO2RTC_BIN", tmp_path / "go2rtc")
    (tmp_path / "go2rtc").write_bytes(b"\x7fELF")  # бинарь уже есть → install не нужен
    written: dict[str, str] = {}
    monkeypatch.setattr(go2rtc, "write_config", lambda src: written.update(src=src))
    monkeypatch.setattr(go2rtc.systemd, "restart", lambda _svc: True)

    assert go2rtc.apply_source("rtsp://new/cam") is True
    assert written["src"] == "rtsp://new/cam"
