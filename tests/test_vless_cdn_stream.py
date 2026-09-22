"""TSK-02: сборка argv ffmpeg — четыре формы источника и синтетический фолбэк."""

from __future__ import annotations

from pathlib import Path

import pytest

from hydra.contracts.vless_cdn import (
    MEDIA_PLAYLIST_PATH,
    MEDIA_SEGMENT_PATH_PREFIX,
    MEDIA_SOURCE_HLS,
    MEDIA_SOURCE_MJPEG,
    MEDIA_SOURCE_RTSP,
    MEDIA_SOURCE_YOUTUBE,
)
from hydra.core.vless_cdn_stream import (
    MEDIA_PLAYLIST_NAME,
    MEDIA_SEGMENT_DIR,
    MEDIA_SEGMENT_TEMPLATE,
    SYNTHETIC,
    hls_output_args,
    media_directory,
    stream_plan,
    synthetic_graph,
    ytdlp_command,
)

OUT = "/var/www/decoy-cdn/api/media"


def _with_ytdlp(*, present: bool):
    return (lambda _name: "/usr/bin/yt-dlp") if present else (lambda _name: None)


def _resolver(mapping):
    """Подмена DNS: тесты не ходят в сеть."""
    return lambda host: list(mapping.get(host, []))


_PUBLIC = _resolver(
    {
        "cam.example": ["93.184.216.34"],
        "video.example": ["93.184.216.34"],
    },
)


# ── Формы источника ─────────────────────────────────────────────────────────────

def test_hls_source_is_used_directly():
    plan = stream_plan("https://cam.example/live/stream.m3u8", output_dir=OUT, resolve=_PUBLIC)

    assert plan.synthetic is False
    assert plan.kind == MEDIA_SOURCE_HLS
    assert plan.reason == ""
    assert plan.command[0] == "ffmpeg"
    assert "-i" in plan.command
    assert plan.command[plan.command.index("-i") + 1] == "https://cam.example/live/stream.m3u8"


def test_rtsp_source_uses_tcp_transport():
    plan = stream_plan("rtsp://cam.example:554/stream", output_dir=OUT, resolve=_PUBLIC)

    assert plan.kind == MEDIA_SOURCE_RTSP
    assert plan.synthetic is False
    assert "-rtsp_transport" in plan.command
    assert plan.command[plan.command.index("-rtsp_transport") + 1] == "tcp"


def test_http_mjpeg_source_reconnects():
    plan = stream_plan("http://cam.example/mjpg/video.mjpg", output_dir=OUT, resolve=_PUBLIC)

    assert plan.kind == MEDIA_SOURCE_MJPEG
    assert plan.synthetic is False
    assert "-reconnect" in plan.command


def test_youtube_with_ytdlp_and_resolved_url():
    plan = stream_plan(
        "https://youtu.be/abc",
        output_dir=OUT,
        which=_with_ytdlp(present=True),
        youtube_stream_url="https://video.example/stream.m3u8",
        resolve=_PUBLIC,
    )

    assert plan.kind == MEDIA_SOURCE_YOUTUBE
    assert plan.synthetic is False
    assert plan.command[plan.command.index("-i") + 1] == "https://video.example/stream.m3u8"


# ── Фолбэк на синтетику (заглушка никогда не мёртвая) ───────────────────────────

def test_empty_source_falls_back_to_synthetic_without_a_complaint():
    plan = stream_plan("", output_dir=OUT)

    assert plan.synthetic is True
    assert plan.kind == SYNTHETIC
    assert plan.reason == ""
    assert plan.command[0] == "ffmpeg"


@pytest.mark.parametrize(
    "url",
    ["ftp://cam.example/x.m3u8", "file:///etc/passwd", "https://10.0.0.1/x.m3u8"],
)
def test_unusable_source_falls_back_to_synthetic_with_reason(url):
    plan = stream_plan(url, output_dir=OUT, which=_with_ytdlp(present=False), resolve=_PUBLIC)

    assert plan.synthetic is True
    assert plan.kind == SYNTHETIC
    assert plan.reason != ""


def test_private_source_is_refused_before_any_stream():
    plan = stream_plan("https://192.168.0.10/x.m3u8", output_dir=OUT)

    assert plan.synthetic is True
    assert "источник отклонён" in plan.reason


def test_youtube_without_ytdlp_is_refused_with_a_reason():
    plan = stream_plan("https://youtu.be/abc", output_dir=OUT, which=_with_ytdlp(present=False))

    assert plan.synthetic is True
    assert "yt-dlp" in plan.reason


def test_youtube_with_ytdlp_but_no_resolved_url_waits_on_synthetic():
    plan = stream_plan("https://youtu.be/abc", output_dir=OUT, which=_with_ytdlp(present=True))

    assert plan.synthetic is True
    assert plan.reason != ""


# ── Единая форма HLS у источника и синтетики ────────────────────────────────────

def test_source_and_synthetic_share_the_exact_hls_tail():
    source = stream_plan("https://cam.example/live/stream.m3u8", output_dir=OUT, resolve=_PUBLIC)
    synthetic = stream_plan("", output_dir=OUT)

    tail = len(hls_output_args(OUT))
    assert source.command[-tail:] == synthetic.command[-tail:] == hls_output_args(OUT)


def test_segmenter_is_a_rolling_hls_window():
    args = hls_output_args(OUT)

    assert args[args.index("-f") + 1] == "hls"
    assert "-hls_time" in args and "-hls_list_size" in args
    assert args[args.index("-hls_flags") + 1] == "delete_segments+omit_endlist"


def test_segment_and_playlist_names_match_the_url_paths():
    args = hls_output_args(OUT)
    base = Path(OUT)

    assert MEDIA_PLAYLIST_PATH.endswith("/" + MEDIA_PLAYLIST_NAME)
    assert MEDIA_SEGMENT_PATH_PREFIX.endswith("/" + MEDIA_SEGMENT_DIR + "/")
    assert args[-1] == str(base / MEDIA_PLAYLIST_NAME)
    assert args[args.index("-hls_segment_filename") + 1] == str(
        base / MEDIA_SEGMENT_DIR / MEDIA_SEGMENT_TEMPLATE,
    )


# ── Синтетическая сцена ─────────────────────────────────────────────────────────

def test_synthetic_scene_is_procedural_and_marks_live():
    graph = synthetic_graph(region="Helsinki", cam_id="CAM-0007", seed="decoy.example")

    assert "color=" in graph
    assert "noise=" in graph
    assert "LIVE" in graph
    assert "localtime" in graph
    assert "CAM-0007" in graph
    assert "Helsinki" in graph
    # Никаких внешних файлов: сцена собрана только источниками lavfi.
    assert ".mp4" not in graph and "http" not in graph


def test_two_domains_do_not_share_a_byte_identical_scene():
    one = synthetic_graph(region="Helsinki", seed="a.example")
    other = synthetic_graph(region="Helsinki", seed="b.example")

    assert one != other


def test_operator_text_cannot_break_the_filter_graph():
    clean = synthetic_graph(region="Helsinki", cam_id="CAM-1", seed="s")
    dirty = synthetic_graph(region="evil':'x,drawtext=text='pwn", cam_id="a:b'c%{x}", seed="s")

    # Инъекция не добавляет новых фильтров и не меняет число кавычек шаблона:
    # операторская пунктуация вырезана, остались только безопасные буквы.
    assert dirty.count("drawtext=") == clean.count("drawtext=")
    assert dirty.count("'") == clean.count("'")
    assert "%{x}" not in dirty


# ── Вспомогательное ─────────────────────────────────────────────────────────────

def test_ytdlp_command_targets_one_stream():
    assert ytdlp_command("https://youtu.be/abc") == [
        "yt-dlp", "-f", "best", "-g", "--no-playlist", "https://youtu.be/abc",
    ]


def test_media_directory_is_under_the_decoy_root():
    assert media_directory().as_posix().endswith("/www/decoy-cdn/" + "api/media")
