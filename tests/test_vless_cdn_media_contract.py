"""TSK-01: медиа-семейство путей, проводные метки и SSRF-проверка источника камеры."""

from __future__ import annotations

import pytest

from hydra.contracts.vless_cdn import (
    DEFAULT_MEDIA_MODE,
    DEFAULT_XHTTP_PATH,
    MEDIA_MODE_PHOTO,
    MEDIA_MODE_VIDEO,
    MEDIA_MODES,
    MEDIA_PADDING_HEADER,
    MEDIA_PATH_PREFIX,
    MEDIA_PLAYLIST_PATH,
    MEDIA_SEGMENT_PATH_PREFIX,
    MEDIA_SEQ_PARAM,
    MEDIA_SESSION_HEADER,
    MEDIA_SOURCE_HLS,
    MEDIA_SOURCE_RTSP,
    STREAM_HLS_TIME_DEFAULT,
    STREAM_IDLE_TIMEOUT_DEFAULT,
    STREAM_LIST_SIZE_DEFAULT,
    as_int_or,
    assert_public_media_source,
    classify_media_source,
    normalize_media_mode,
    normalize_path,
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
    ],
)
def test_source_form_is_read_from_scheme_and_host(url, expected):
    assert classify_media_source(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://cam.example/x.m3u8",
        "file:///etc/passwd",
        "https://",
        "cam.example/x.m3u8",
        # YouTube — не форма, а отказ: страница-смотрильня требует отдельного резолвера,
        # которого у нас нет. Раньше такой URL проходил проверку, сохранялся, а потом
        # молча давал мёртвый плеер.
        "https://www.youtube.com/watch?v=abc",
        "https://youtu.be/abc",
        "https://m.youtube.com/watch?v=abc",
        # MJPEG и прочий http-поток: ни HLS, ни MSE его не несут, то есть источник
        # сохранился бы и не играл. Отказ должен быть на входе, а не в пустом плеере.
        "http://cam.example/mjpg/video.mjpg",
        "https://cam.example/video",
    ],
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


def test_youtube_is_refused_before_any_resolution():
    # Отказ должен быть внятным и до сети: иначе оператор сохраняет источник, который не
    # играет, и не имеет ни одной зацепки — почему.
    def explode(_host: str) -> list[str]:
        raise AssertionError("youtube не должен доходить до резолвера")

    with pytest.raises(ValueError, match="YouTube"):
        assert_public_media_source("https://youtu.be/abc", resolve=explode)


def test_ssrf_refuses_bad_scheme_before_any_resolution():
    def explode(_host: str) -> list[str]:
        raise AssertionError("резолвер не должен вызываться")

    with pytest.raises(ValueError):
        assert_public_media_source("file:///etc/passwd", resolve=explode)


# ── Префикс прежней ретрансляции: читаем, но не пишем ──────────────────────────


def test_legacy_prefix_still_reads_the_inner_url():
    # Префикс `ffmpeg:` остался от прежней ретрансляции через go2rtc: он уходил в её конфиг
    # как есть. Наш код его больше не пишет, но обязан прочитать сохранённый — иначе
    # развёрнутая машина после обновления перестанет понимать собственный источник.
    url = "ffmpeg:https://8.8.8.8/x.m3u8"
    assert classify_media_source(url) == MEDIA_SOURCE_HLS
    assert assert_public_media_source(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "ffmpeg:https://127.0.0.1/x.m3u8",
        "ffmpeg:https://10.0.0.1/x.m3u8",
        "ffmpeg:https://[::1]/x.m3u8",
        "ffmpeg:file:///etc/passwd",
    ],
)
def test_legacy_prefix_does_not_bypass_the_source_checks(url):
    # Префикс — не лазейка: форма и SSRF проверяются по тому, что за ним.
    with pytest.raises(ValueError):
        assert_public_media_source(url)


# ── Настройки потока ───────────────────────────────────────────────────────────


def test_stream_setting_defaults_keep_the_window_wide():
    # Окно в десять сегментов — это десятки секунд запаса, и именно оно делает поток
    # терпимым к задержке через CDN. Прошлый ретранслятор держал одну секунду.
    assert STREAM_LIST_SIZE_DEFAULT >= 10
    assert STREAM_HLS_TIME_DEFAULT >= 1
    assert STREAM_IDLE_TIMEOUT_DEFAULT > 0


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        (None, 120, 120),
        ("", 120, 120),
        (0, 120, 0),  # ноль — законное значение: «не гасить»
        ("45", 120, 45),
        ("мусор", 120, 0),
    ],
)
def test_stream_setting_reads_the_state_with_a_default(value, default, expected):
    assert as_int_or(value, default) == expected


# ── Режим медиа ────────────────────────────────────────────────────────────────


def test_media_modes_are_video_and_photo_with_video_as_default():
    assert MEDIA_MODES == (MEDIA_MODE_VIDEO, MEDIA_MODE_PHOTO)
    assert DEFAULT_MEDIA_MODE == MEDIA_MODE_VIDEO


@pytest.mark.parametrize("value", ["video", "VIDEO", " video ", MEDIA_MODE_PHOTO, "Photo"])
def test_known_media_mode_survives_normalization(value):
    assert normalize_media_mode(value) in MEDIA_MODES


@pytest.mark.parametrize("value", ["", None, "фото", "synthetic", 42])
def test_unknown_media_mode_falls_back_to_the_default(value):
    # Состояние без поля и опечатка оператора ведут себя одинаково — как было до появления
    # режима, то есть видео: старая инсталляция не должна внезапно показать фото.
    assert normalize_media_mode(value) == DEFAULT_MEDIA_MODE
