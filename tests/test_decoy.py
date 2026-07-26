from unittest.mock import patch

import pytest

from hydra.core import decoy
from hydra.core.decoy import DECOY_DIRS, ensure_decoy_site


THEME_CASES = {
    "naive": {
        "marker": "Apex Digital Agency",
        "files": {"index.html", "about.html", "contact.html", "css/style.css"},
    },
    "anytls": {
        "marker": "TechBits",
        "files": {
            "index.html",
            "about.html",
            "post-1.html",
            "post-2.html",
            "css/style.css",
        },
    },
    "trusttunnel": {
        "marker": "HydraDB Docs",
        "files": {
            "index.html",
            "getting-started.html",
            "api-reference.html",
            "css/style.css",
        },
    },
    "hysteria2": {
        "marker": "Northstar Cloud Status",
        "files": {"index.html", "status.json", "css/style.css"},
    },
}


@pytest.mark.parametrize(("plugin_name", "expectation"), THEME_CASES.items())
def test_every_plugin_generates_its_theme(tmp_path, plugin_name, expectation):
    site_dir = tmp_path / plugin_name
    with patch.dict(DECOY_DIRS, {plugin_name: site_dir}):
        assert ensure_decoy_site(plugin_name) == site_dir

    generated = {
        path.relative_to(site_dir).as_posix()
        for path in site_dir.rglob("*")
        if path.is_file()
    }
    assert expectation["files"] <= generated
    assert expectation["marker"] in (site_dir / "index.html").read_text(
        encoding="utf-8",
    )
    assert {"robots.txt", "favicon.ico"} <= generated
    assert (site_dir / "js").is_dir()
    assert (site_dir / "images").is_dir()


def test_unknown_plugin_is_rejected():
    with pytest.raises(ValueError, match="Unknown plugin for decoy: missing"):
        ensure_decoy_site("missing")


def test_existing_site_is_not_regenerated(tmp_path):
    site_dir = tmp_path / "naive"
    site_dir.mkdir()
    index = site_dir / "index.html"
    index.write_text("operator-managed content", encoding="utf-8")

    with (
        patch.dict(DECOY_DIRS, {"naive": site_dir}),
        patch.object(decoy, "_create_site") as create_site,
    ):
        assert ensure_decoy_site("naive") == site_dir
        assert ensure_decoy_site("naive") == site_dir

    create_site.assert_not_called()
    assert index.read_text(encoding="utf-8") == "operator-managed content"


def test_theme_dispatch_keeps_legacy_monkeypatch_seams(tmp_path):
    landing = patch.object(decoy, "_generate_landing")
    bootstrap = patch.object(decoy, "_prepare_site")
    with landing as generate, bootstrap as prepare:
        decoy._create_site(tmp_path, "landing")

    prepare.assert_called_once_with(tmp_path)
    generate.assert_called_once_with(tmp_path)


def test_ensure_resolves_create_site_monkeypatch_at_call_time(tmp_path):
    site_dir = tmp_path / "naive"
    with (
        patch.dict(DECOY_DIRS, {"naive": site_dir}),
        patch.object(decoy, "_create_site") as create_site,
    ):
        assert ensure_decoy_site("naive") == site_dir

    create_site.assert_called_once_with(site_dir, "landing")


def test_hysteria2_has_its_own_status_decoy(tmp_path):
    site_dir = tmp_path / "hysteria2"
    with patch.dict(DECOY_DIRS, {"hysteria2": site_dir}):
        assert ensure_decoy_site("hysteria2") == site_dir

    index = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "Northstar Cloud Status" in index
    assert "All systems operational" in index
    assert (site_dir / "css" / "style.css").is_file()
    assert (site_dir / "status.json").is_file()


def test_vless_media_theme_is_distinct_and_content_rich(tmp_path):
    site_dir = tmp_path / "vless"

    decoy._create_site(site_dir, "media")

    generated = {
        path.relative_to(site_dir).as_posix()
        for path in site_dir.rglob("*")
        if path.is_file()
    }
    assert {
        "index.html",
        "technology.html",
        "business.html",
        "culture.html",
        "about.html",
        "css/style.css",
        "js/site.js",
        "robots.txt",
        "sitemap.xml",
        "site.webmanifest",
    } <= generated

    index = (site_dir / "index.html").read_text(encoding="utf-8")
    styles = (site_dir / "css" / "style.css").read_text(encoding="utf-8")
    assert "Meridian Daily" in index
    assert "Latest stories" in index
    assert "Most read" in index
    assert "Apex Digital Agency" not in index
    assert "@media" in styles
