"""TSK-01: медиа-семейство путей, проводные метки и SSRF-проверка источника камеры."""

from __future__ import annotations

import pytest

from hydra.contracts.vless_cdn import (
    DEFAULT_XHTTP_PATH,
    MEDIA_PADDING_HEADER,
    MEDIA_PATH_PREFIX,
    MEDIA_PLAYLIST_PATH,
    MEDIA_SEGMENT_PATH_PREFIX,
    MEDIA_SEQ_PARAM,
    MEDIA_SESSION_HEADER,
    MEDIA_SOURCE_HLS,
    MEDIA_SOURCE_MJPEG,
    MEDIA_SOURCE_RTSP,
    MEDIA_SOURCE_YOUTUBE,
    assert_public_media_source,
    classify_media_source,
    normalize_path,
    parse_hls_relay_source,
    playlist_segments_are_relative,
)


# ── Путь живёт внутри медиа-семейства (R4) ──────────────────────────────────────


def test_default_path_sits_inside_the_media_family():
    assert DEFAULT_XHTTP_PATH.startswith(f"{MEDIA_PATH_PREFIX}/")
    assert normalize_path(DEFAULT_XHTTP_PATH) == DEFAULT_XHTTP_PATH


@pytest.mark.parametrize(
    "value",
    ["/api/media/session", "/api/media/live/session", "/api/media/session/"],
)
def test_path_inside_the_media_family_is_accepted(value):
    assert normalize_path(value).startswith(f"{MEDIA_PATH_PREFIX}/")


@pytest.mark.parametrize(
    "value",
    [
        "/api/session",  # вне семейства
        "/vless",  # вне семейства
        "/media/session",  # похоже, но не префикс
        f"{MEDIA_PATH_PREFIX}",  # голый префикс — это не подпуть
        "/assets/logo.png",  # зарезервировано
        "/api/ media/session",  # пробел
        "/",
        "",
    ],
)
def test_path_outside_the_media_family_is_refused(value):
    with pytest.raises(ValueError):
        normalize_path(value)


def test_media_subpaths_are_built_from_the_prefix():
    assert MEDIA_PLAYLIST_PATH == f"{MEDIA_PATH_PREFIX}/playlist.m3u8"
    assert MEDIA_SEGMENT_PATH_PREFIX == f"{MEDIA_PATH_PREFIX}/seg/"


# ── Проводные метки совпадают с транспортом (R4.1) ──────────────────────────────


def test_wire_marks_match_the_transport_exactly():
    from hydra.plugins.vless_cdn.profile import SEQ_KEY, SESSION_KEY, X_PADDING_HEADER

    assert MEDIA_SESSION_HEADER == SESSION_KEY == "X-Upload-Token"
    assert MEDIA_SEQ_PARAM == SEQ_KEY == "chunk_id"
    assert MEDIA_PADDING_HEADER == X_PADDING_HEADER == "X-Client-Version"


# ── Классификация источника по форме ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://cam.example/live/stream.m3u8", MEDIA_SOURCE_HLS),
        ("http://cam.example/live/stream.M3U8", MEDIA_SOURCE_HLS),
        ("rtsp://cam.example:554/stream", MEDIA_SOURCE_RTSP),
        ("http://cam.example/mjpg/video.mjpg", MEDIA_SOURCE_MJPEG),
        ("https://cam.example/video", MEDIA_SOURCE_MJPEG),
        ("https://www.youtube.com/watch?v=abc", MEDIA_SOURCE_YOUTUBE),
        ("https://youtu.be/abc", MEDIA_SOURCE_YOUTUBE),
        ("https://m.youtube.com/watch?v=abc", MEDIA_SOURCE_YOUTUBE),
    ],
)
def test_source_form_is_read_from_scheme_and_host(url, expected):
    assert classify_media_source(url) == expected


@pytest.mark.parametrize(
    "url",
    ["", "   ", "ftp://cam.example/x.m3u8", "file:///etc/passwd", "https://", "cam.example/x.m3u8"],
)
def test_source_form_refuses_what_it_cannot_play(url):
    with pytest.raises(ValueError):
        classify_media_source(url)


# ── SSRF: источник не должен указывать внутрь (R-NFR-security) ──────────────────


def _resolver(mapping):
    def resolve(host: str) -> list[str]:
        return list(mapping.get(host, []))

    return resolve


def test_public_literal_address_is_accepted():
    assert assert_public_media_source("https://8.8.8.8/x.m3u8") == "https://8.8.8.8/x.m3u8"


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.1/x.m3u8",
        "https://127.0.0.1/x.m3u8",
        "https://169.254.1.1/x.m3u8",
        "https://192.168.1.1/x.m3u8",
        "https://[::1]/x.m3u8",
        "rtsp://10.0.0.1/stream",
    ],
)
def test_private_or_local_literal_is_refused(url):
    with pytest.raises(ValueError):
        assert_public_media_source(url)


def test_hostname_must_resolve_to_public_addresses_only():
    resolve = _resolver({"cam.example": ["93.184.216.34"]})
    assert assert_public_media_source("https://cam.example/x.m3u8", resolve=resolve).endswith("x.m3u8")

    private = _resolver({"cam.example": ["10.0.0.5", "93.184.216.34"]})
    with pytest.raises(ValueError):
        assert_public_media_source("https://cam.example/x.m3u8", resolve=private)


def test_unresolvable_host_is_refused():
    with pytest.raises(ValueError):
        assert_public_media_source("https://nowhere.example/x.m3u8", resolve=_resolver({}))


def test_youtube_host_needs_no_resolution():
    # Youtube — известный публичный хост: резолвер, который бы упал, не вызывается.
    def explode(_host: str) -> list[str]:
        raise AssertionError("youtube не должен резолвиться")

    assert assert_public_media_source("https://youtu.be/abc", resolve=explode).startswith("https://youtu.be/")


def test_ssrf_refuses_bad_scheme_before_any_resolution():
    def explode(_host: str) -> list[str]:
        raise AssertionError("резолвер не должен вызываться")

    with pytest.raises(ValueError):
        assert_public_media_source("file:///etc/passwd", resolve=explode)


# ── Разбор HLS-источника под reverse_proxy ────────────────────────────────


def test_relay_parse_splits_host_dir_and_playlist():
    src = parse_hls_relay_source(
        "https://8.8.8.8/camera01/tracks-v1/index.fmp4.m3u8",
    )
    assert src == {
        "host": "8.8.8.8",
        "port": 443,
        "tls": True,
        "dir": "/camera01/tracks-v1",
        "playlist": "index.fmp4.m3u8",
    }


def test_relay_parse_rejects_non_hls_and_private_and_empty():
    # RTSP/MJPEG/YouTube не ретранслируются чистым proxy → None.
    assert parse_hls_relay_source("rtsp://8.8.8.8/live") is None
    assert parse_hls_relay_source("https://youtu.be/abc") is None
    assert parse_hls_relay_source("") is None
    # Приватный адрес (SSRF) — тоже None, без исключения.
    assert parse_hls_relay_source("https://10.0.0.5/x.m3u8") is None


def test_relative_segment_playlist_is_relayable():
    # Голые имена сегментов + fMP4-init через EXT-X-MAP URI — всё относительное.
    playlist = '#EXTM3U\n#EXT-X-MAP:URI="init.hls.fmp4"\n#EXTINF:4,\nseg-0.hls.fmp4\n'
    assert playlist_segments_are_relative(playlist) is True
    # Только .ts без схемы — тоже относительно.
    assert playlist_segments_are_relative("#EXTM3U\n#EXTINF:4,\nlive128.ts\n") is True


def test_absolute_segment_playlist_is_not_relayable():
    # Абсолютный сегмент → плеер уйдёт с нашего домена.
    assert playlist_segments_are_relative("#EXTM3U\n#EXTINF:4,\nhttps://cdn.x/seg-0.ts\n") is False
    # Абсолютный init через EXT-X-MAP — тоже нет.
    assert playlist_segments_are_relative('#EXT-X-MAP:URI="https://cdn.x/init.mp4"\nseg-0.ts\n') is False
    # Пустой/без сегментов — нечего ретранслировать.
    assert playlist_segments_are_relative("#EXTM3U\n#EXT-X-ENDLIST\n") is False
    assert playlist_segments_are_relative("") is False


def test_relay_parse_reads_explicit_port_and_http():
    src = parse_hls_relay_source("http://8.8.8.8:8080/hls/live.m3u8")
    assert src == {
        "host": "8.8.8.8",
        "port": 8080,
        "tls": False,
        "dir": "/hls",
        "playlist": "live.m3u8",
    }
