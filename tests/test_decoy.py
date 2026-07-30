from unittest.mock import patch

import pytest

from hydra.core.decoy import (
    DECOY_DIRS,
    SUPPORTED_THEMES,
    default_theme,
    ensure_decoy_site,
    ensure_site,
)
from hydra.core.decoy_sites import builder
from hydra.core.decoy_sites.identity import build_identity
from hydra.core.decoy_sites.registry import THEME_NAMES, THEMES


def _files(site_dir) -> set[str]:
    return {
        path.relative_to(site_dir).as_posix()
        for path in site_dir.rglob("*")
        if path.is_file()
    }


def _render(site_dir, theme: str, domain: str) -> None:
    builder.build(
        site_dir,
        theme,
        THEMES[theme].render,
        build_identity(domain),
    )


@pytest.mark.parametrize("theme", THEME_NAMES)
def test_every_theme_publishes_a_complete_site(tmp_path, theme):
    site_dir = tmp_path / theme

    _render(site_dir, theme, "site.example.com")

    generated = _files(site_dir)
    assert {
        "index.html",
        "404.html",
        "css/style.css",
        "robots.txt",
        "sitemap.xml",
        "favicon.ico",
        ".hydra-decoy.json",
    } <= generated
    index = (site_dir / "index.html").read_text(encoding="utf-8")
    styles = (site_dir / "css" / "style.css").read_text(encoding="utf-8")
    assert index.startswith("<!DOCTYPE html>") and index.rstrip().endswith(
        "</html>",
    )
    assert "site.example.com" in (site_dir / "robots.txt").read_text(
        encoding="utf-8",
    )
    assert "@media" in styles and "--accent" in styles
    assert (site_dir / "js").is_dir() and (site_dir / "images").is_dir()


@pytest.mark.parametrize("theme", THEME_NAMES)
def test_two_installations_do_not_serve_identical_markup(tmp_path, theme):
    first = tmp_path / "first"
    second = tmp_path / "second"

    _render(first, theme, "one.example.com")
    _render(second, theme, "two.example.net")

    assert (first / "index.html").read_text(encoding="utf-8") != (
        second / "index.html"
    ).read_text(encoding="utf-8")
    assert (first / "favicon.ico").read_bytes() != (
        second / "favicon.ico"
    ).read_bytes()


def test_same_domain_and_theme_render_reproducibly(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    _render(first, "landing", "stable.example.com")
    _render(second, "landing", "stable.example.com")

    assert (first / "index.html").read_bytes() == (
        second / "index.html"
    ).read_bytes()


def test_theme_change_republishes_the_site(tmp_path):
    site_dir = tmp_path / "decoy-a"

    _render(site_dir, "landing", "switch.example.com")
    before = (site_dir / "index.html").read_text(encoding="utf-8")
    _render(site_dir, "cafe", "switch.example.com")
    after = (site_dir / "index.html").read_text(encoding="utf-8")

    assert before != after
    assert "\"theme\": \"cafe\"" in (
        site_dir / ".hydra-decoy.json"
    ).read_text(encoding="utf-8")
    assert not (site_dir / "about.html").exists()


def test_published_site_is_current_until_theme_or_domain_changes(tmp_path):
    site_dir = tmp_path / "decoy-b"
    identity = build_identity("current.example.com")
    _render(site_dir, "docs", "current.example.com")

    assert builder.is_current(site_dir, "docs", identity)
    assert not builder.is_current(site_dir, "blog", identity)
    assert not builder.is_current(
        site_dir,
        "docs",
        build_identity("other.example.com"),
    )


def test_published_site_is_stale_when_renderer_sources_change(tmp_path):
    site_dir = tmp_path / "decoy-renderer"
    sources = tmp_path / "renderer-sources"
    sources.mkdir()
    source = sources / "theme.py"
    source.write_text("VERSION = 1\n", encoding="utf-8")
    identity = build_identity("renderer.example.com")

    with patch.object(builder, "SOURCE_ROOT", sources):
        _render(site_dir, "landing", "renderer.example.com")
        assert builder.is_current(site_dir, "landing", identity)

        source.write_text("VERSION = 2\n", encoding="utf-8")

        assert not builder.is_current(site_dir, "landing", identity)


def test_legacy_generated_marker_is_rebuilt_once(tmp_path):
    site_dir = tmp_path / "decoy-legacy"
    identity = build_identity("legacy.example.com")
    _render(site_dir, "blog", "legacy.example.com")
    marker = site_dir / ".hydra-decoy.json"
    marker.write_text(
        '{\n'
        '  "theme": "blog",\n'
        f'  "identity": "{identity.fingerprint}",\n'
        '  "domain": "legacy.example.com"\n'
        '}\n',
        encoding="utf-8",
    )

    assert not builder.is_current(site_dir, "blog", identity)


@pytest.mark.parametrize(
    "legacy_index",
    (
        (
            "<title>Apex Digital Agency | Home</title>"
            "Apex<span>Digital</span>"
            "We Build Premium Digital Products"
        ),
        (
            "<title>TechBits | Insights on Modern Software</title>"
            "Tech<span>Bits</span>"
            "The Evolution of WebAssembly in the Cloud Native Stack"
        ),
        (
            "<title>HydraDB Docs | Ultimate Time-Series Storage</title>"
            '<a class="brand">HydraDB</a>'
            "<h1>What is HydraDB?</h1>"
        ),
        (
            "<title>Independent news and ideas | Meridian Daily</title>"
            "Meridian <b>Daily</b>"
            "How public spaces are being redesigned for a warmer world"
        ),
        (
            "<title>Northstar Cloud Status</title>"
            "Northstar Cloud infrastructure status"
            "All systems operational"
        ),
    ),
)
def test_legacy_generated_site_without_marker_is_rebuilt(
    tmp_path,
    legacy_index,
):
    site_dir = tmp_path / "decoy-c"
    site_dir.mkdir()
    (site_dir / "index.html").write_text(
        f"<!DOCTYPE html><html>{legacy_index}</html>",
        encoding="utf-8",
    )
    identity = build_identity("trusttunnel.example.com")

    assert not builder.is_current(site_dir, "gallery", identity)

    builder.build(
        site_dir,
        "gallery",
        THEMES["gallery"].render,
        identity,
    )

    assert builder.is_current(site_dir, "gallery", identity)
    marker = (site_dir / ".hydra-decoy.json").read_text(encoding="utf-8")
    assert '"theme": "gallery"' in marker
    assert legacy_index not in (site_dir / "index.html").read_text(
        encoding="utf-8",
    )


def test_operator_managed_site_is_never_replaced(tmp_path):
    site_dir = tmp_path / "decoy-c"
    site_dir.mkdir()
    (site_dir / "index.html").write_text("operator content", encoding="utf-8")

    assert builder.is_current(site_dir, "blog", build_identity("x.example.com"))


def test_operator_site_is_not_adopted_from_one_legacy_phrase(tmp_path):
    site_dir = tmp_path / "decoy-operator"
    site_dir.mkdir()
    (site_dir / "index.html").write_text(
        "<h1>What is HydraDB?</h1><p>Operator content</p>",
        encoding="utf-8",
    )

    assert builder.is_current(
        site_dir,
        "gallery",
        build_identity("operator.example.com"),
    )


def test_failed_legacy_rebuild_keeps_the_unmarked_site(tmp_path):
    site_dir = tmp_path / "decoy-legacy-failure"
    site_dir.mkdir()
    legacy = (
        "<title>HydraDB Docs | Ultimate Time-Series Storage</title>"
        '<a class="brand">HydraDB</a>'
        "<h1>What is HydraDB?</h1>"
    )
    (site_dir / "index.html").write_text(legacy, encoding="utf-8")
    identity = build_identity("trusttunnel.example.com")

    def broken(_site_dir, _identity):
        raise RuntimeError("renderer failed")

    assert not builder.is_current(site_dir, "cafe", identity)
    with pytest.raises(RuntimeError, match="renderer failed"):
        builder.build(site_dir, "cafe", broken, identity)

    assert (site_dir / "index.html").read_text(encoding="utf-8") == legacy
    assert not (site_dir / ".hydra-decoy.json").exists()


def test_failed_render_keeps_the_previous_site(tmp_path):
    site_dir = tmp_path / "decoy-d"
    _render(site_dir, "status", "keep.example.com")
    published = (site_dir / "index.html").read_text(encoding="utf-8")

    def broken(_site_dir, _identity):
        raise RuntimeError("renderer failed")

    with pytest.raises(RuntimeError, match="renderer failed"):
        builder.build(
            site_dir,
            "cafe",
            broken,
            build_identity("keep.example.com"),
        )

    assert (site_dir / "index.html").read_text(encoding="utf-8") == published
    assert not site_dir.with_name(f"{site_dir.name}.staging").exists()


def test_renderer_fingerprint_failure_keeps_the_previous_site(tmp_path):
    site_dir = tmp_path / "decoy-fingerprint-failure"
    _render(site_dir, "status", "fingerprint.example.com")
    published = (site_dir / "index.html").read_bytes()

    with patch.object(
        builder,
        "_renderer_revision",
        side_effect=OSError("source read failed"),
    ), pytest.raises(OSError, match="source read failed"):
        _render(site_dir, "status", "fingerprint.example.com")

    assert (site_dir / "index.html").read_bytes() == published
    assert not site_dir.with_name(f"{site_dir.name}.staging").exists()


def test_plugin_site_uses_its_default_theme_and_domain_seed():
    with patch("hydra.core.decoy.ensure_site") as publish:
        ensure_decoy_site("naive", domain="naive.example.com")

    assert publish.call_args[0][0] == DECOY_DIRS["naive"]
    assert publish.call_args[0][1] == default_theme("naive") == "landing"
    assert publish.call_args[1] == {"domain": "naive.example.com"}


def test_configured_theme_overrides_the_plugin_default(tmp_path):
    site_dir = tmp_path / "decoy-hysteria2"

    with patch.dict(DECOY_DIRS, {"hysteria2": site_dir}), patch(
        "hydra.core.decoy.ensure_site",
    ) as publish:
        ensure_decoy_site("hysteria2", "gallery", domain="hy.example.com")

    assert publish.call_args[0][1] == "gallery"


def test_publishing_records_theme_domain_and_identity(tmp_path):
    site_dir = tmp_path / "decoy-marker"

    _render(site_dir, "gallery", "hy.example.com")

    marker = (site_dir / ".hydra-decoy.json").read_text(encoding="utf-8")
    assert '"theme": "gallery"' in marker
    assert '"domain": "hy.example.com"' in marker
    assert build_identity("hy.example.com").fingerprint in marker
    assert '"renderer_revision": "' in marker


def test_unknown_plugin_and_theme_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unknown plugin for decoy: missing"):
        ensure_decoy_site("missing")
    with pytest.raises(ValueError, match="Unknown decoy theme"):
        ensure_site(tmp_path / "decoy-x", "not-a-theme")


def test_site_outside_the_decoy_root_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="must be under /var/www/decoy"):
        ensure_site(tmp_path / "elsewhere", "landing")


def test_catalogue_and_facade_agree_on_supported_themes():
    assert SUPPORTED_THEMES == set(THEME_NAMES)
    assert len(THEME_NAMES) >= 11
    assert {theme.label for theme in THEMES.values()} == {
        theme.label for theme in THEMES.values()
    }
    assert all(theme.description for theme in THEMES.values())
