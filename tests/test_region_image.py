"""TSK-008: изображение региона — разбор ответа, обновление раз в 12 часов, запасной файл."""
from __future__ import annotations

from pathlib import Path

from hydra.core.region_image import (
    IMAGE_NAME,
    IMAGE_SRC,
    PLACEHOLDER_NAME,
    PLACEHOLDER_SRC,
    REFRESH_SECONDS,
    RegionImage,
    parse_search,
    placeholder_svg,
    refresh_region_image,
)

PAYLOAD = {
    "query": {
        "pages": {
            "123": {
                "title": "File:Skyline Frankfurt am Main 2015.jpg",
                "imageinfo": [
                    {
                        "thumburl": "https://upload.wikimedia.org/thumb/region.jpg",
                        "url": "https://upload.wikimedia.org/region.jpg",
                        "extmetadata": {
                            "Artist": {"value": '<a href="/wiki/User:X">Christian Wolf</a>'},
                            "LicenseShortName": {"value": "CC BY-SA 3.0 de"},
                            "LicenseUrl": {"value": "https://creativecommons.org/licenses/by-sa/3.0/de/deed.en"},
                            "Credit": {"value": "Own work"},
                        },
                    },
                ],
            },
        },
    },
}

PHOTO = b"\xff" * 8192  # достаточно крупный «файл», чтобы пройти проверку размера


def _search(image: RegionImage | None = None, calls: list | None = None):
    log = calls if calls is not None else []

    def find(query: str) -> RegionImage | None:
        log.append(query)
        return image

    return find, log


def _download(data: bytes | None = PHOTO, calls: list | None = None):
    log = calls if calls is not None else []

    def fetch(url: str) -> bytes | None:
        log.append(url)
        return data

    return fetch, log


def test_search_answer_is_parsed_with_its_attribution():
    image = parse_search(PAYLOAD)

    assert image is not None
    assert image.src == "https://upload.wikimedia.org/thumb/region.jpg"
    assert image.source == "File:Skyline Frankfurt am Main 2015.jpg"
    assert image.attribution == "Christian Wolf, CC BY-SA 3.0 de", "теги вырезаны, лицензия рядом"


def test_search_answer_without_a_usable_file_is_ignored():
    assert parse_search(None) is None
    assert parse_search({}) is None
    assert parse_search({"query": {"pages": {}}}) is None
    assert parse_search({"query": {"pages": {"1": {"title": "File:X.jpg"}}}}) is None
    assert parse_search({"query": {"pages": {"1": {"imageinfo": [{"url": "ftp://x"}]}}}}) is None


def test_placeholder_is_local_and_never_a_remote_reference():
    svg = placeholder_svg()

    assert svg.startswith("<svg")
    assert "href" not in svg, "запасной файл не должен тянуть что-то извне"
    assert "url(" in svg


def test_first_run_downloads_the_image_and_keeps_a_placeholder(tmp_path):
    find, _ = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg", attribution="A, CC0", source="File:R"))
    fetch, _ = _download()

    image = refresh_region_image(tmp_path, query="Frankfurt Germany", now=100, search=find, download=fetch)

    assert image.refreshed is True
    assert image.src == IMAGE_SRC
    assert image.attribution == "A, CC0"
    assert (Path(tmp_path) / "assets" / IMAGE_NAME).read_bytes() == PHOTO
    assert (Path(tmp_path) / "assets" / PLACEHOLDER_NAME).exists(), "запасной файл лежит рядом"
    assert not list(Path(tmp_path).glob("**/*.tmp")), "временных файлов не осталось"


def test_inside_the_window_nothing_is_requested_again(tmp_path):
    find, searches = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))
    fetch, downloads = _download()
    refresh_region_image(tmp_path, query="Frankfurt", now=100, search=find, download=fetch)

    image = refresh_region_image(
        tmp_path,
        query="Frankfurt",
        last_updated=100,
        now=100 + REFRESH_SECONDS - 60,
        search=find,
        download=fetch,
    )

    assert image.refreshed is False
    assert image.src == IMAGE_SRC
    assert len(searches) == 1
    assert len(downloads) == 1


def test_after_the_window_the_image_is_refreshed(tmp_path):
    find, searches = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))
    fetch, _ = _download()
    refresh_region_image(tmp_path, query="Frankfurt", now=100, search=find, download=fetch)

    refresh_region_image(
        tmp_path,
        query="Frankfurt",
        last_updated=100,
        now=100 + REFRESH_SECONDS + 1,
        search=find,
        download=fetch,
    )

    assert len(searches) == 2


def test_forced_refresh_ignores_the_window(tmp_path):
    find, searches = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))
    fetch, _ = _download()
    refresh_region_image(tmp_path, query="Frankfurt", now=100, search=find, download=fetch)
    refresh_region_image(
        tmp_path,
        query="Frankfurt",
        last_updated=100,
        now=101,
        force=True,
        search=find,
        download=fetch,
    )

    assert len(searches) == 2


def test_nothing_found_keeps_the_previous_picture(tmp_path):
    good, _ = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))
    fetch, _ = _download()
    refresh_region_image(tmp_path, query="Frankfurt", now=100, search=good, download=fetch)
    before = (Path(tmp_path) / "assets" / IMAGE_NAME).read_bytes()

    empty, _ = _search(None)
    image = refresh_region_image(
        tmp_path,
        query="Frankfurt",
        last_updated=100,
        now=100 + REFRESH_SECONDS + 1,
        search=empty,
        download=fetch,
    )

    assert image.refreshed is False
    assert image.src == IMAGE_SRC
    assert (Path(tmp_path) / "assets" / IMAGE_NAME).read_bytes() == before


def test_a_broken_download_does_not_replace_a_working_picture(tmp_path):
    good, _ = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))
    fetch, _ = _download()
    refresh_region_image(tmp_path, query="Frankfurt", now=100, search=good, download=fetch)
    before = (Path(tmp_path) / "assets" / IMAGE_NAME).read_bytes()

    broken, _ = _download(data=None)
    image = refresh_region_image(
        tmp_path,
        query="Frankfurt",
        last_updated=100,
        now=100 + REFRESH_SECONDS + 1,
        search=good,
        download=broken,
    )

    assert image.refreshed is False
    assert (Path(tmp_path) / "assets" / IMAGE_NAME).read_bytes() == before


def test_a_too_small_or_too_large_file_is_rejected(tmp_path):
    find, _ = _search(RegionImage(src="https://upload.wikimedia.org/thumb/region.jpg"))

    for data in (b"tiny", b"\xff" * (7 * 1024 * 1024)):
        fetch, _ = _download(data=data)
        image = refresh_region_image(tmp_path, query="Frankfurt", now=100, search=find, download=fetch)
        assert image.refreshed is False
        assert image.src == PLACEHOLDER_SRC, "лучше запасной файл, чем мусор"
        assert not (Path(tmp_path) / "assets" / IMAGE_NAME).exists()


def test_without_any_picture_the_page_gets_the_placeholder(tmp_path):
    empty, _ = _search(None)
    fetch, _ = _download()

    image = refresh_region_image(tmp_path, query="Frankfurt", now=100, search=empty, download=fetch)

    assert image.src == PLACEHOLDER_SRC
    assert image.refreshed is False
    assert (Path(tmp_path) / "assets" / PLACEHOLDER_NAME).exists()
