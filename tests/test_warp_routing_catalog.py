"""Routing categories, the rule catalogue, and the source-key migration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hydra.core.state_migrations import _normalize_warp_sources
from hydra.plugins.warp import catalog, routing_catalog
from hydra.plugins.warp.routing_catalog import (
    build_routing_catalog,
    category_menu,
    category_target,
)


def _catalog() -> dict[str, dict[str, str]]:
    return {
        "refilter": {
            "name": "Реестр РКН",
            "url": "https://example.test/refilter.txt",
            "desc": "Заблокированное в РФ",
            "group": "blocked",
        },
        "antifilter": {
            "name": "Антифильтр (IP)",
            "url": "https://example.test/antifilter.txt",
            "desc": "Заблокированные IP-диапазоны",
            "group": "blocked",
        },
        "category-ru": {
            "name": "Все российские сервисы",
            "url": "https://example.test/category-ru.txt",
            "desc": "Российские сервисы",
            "group": "ru",
        },
        "youtube": {
            "name": "YouTube",
            "url": "https://example.test/youtube.txt",
            "desc": "Медиа и стриминг",
            "group": "media",
        },
        "netflix": {
            "name": "Netflix",
            "url": "https://example.test/netflix.txt",
            "desc": "Медиа и стриминг",
            "group": "media",
        },
        "category-ai": {
            "name": "Все AI-сервисы",
            "url": "https://example.test/category-ai.txt",
            "desc": "AI",
            "group": "ai",
        },
    }


def _category(categories: list, key: str):
    return next(item for item in categories if item.key == key)


def test_routing_catalog_excludes_rollups_and_itdog_sources() -> None:
    categories = build_routing_catalog(
        _catalog()
        | {
            "itDog-russia-inside": {"name": "itDog", "url": "u", "group": "ru"},
        },
        {},
    )
    keys = {key for category in categories for key in category.source_keys}
    assert keys == {"ext:youtube", "ext:netflix"}


def test_catalog_groups_sources_by_their_category() -> None:
    categories = build_routing_catalog(_catalog(), {})

    assert {item.key for item in categories} == {"media"}
    media = _category(categories, "media")
    assert media.label == "Медиа и стриминг"
    assert media.source_keys == ("ext:netflix", "ext:youtube")

    assert media.direction == "warp"


def test_category_target_reports_uniform_and_mixed_routes() -> None:
    category = _category(build_routing_catalog(_catalog(), {}), "media")

    assert category_target(category, {}) == "none"
    assert category_target(category, {"ext:youtube": "none"}) == "none"
    assert (
        category_target(
            category,
            {"ext:youtube": "warp", "ext:netflix": "warp"},
        )
        == "warp"
    )
    assert (
        category_target(
            category,
            {"ext:youtube": "warp", "ext:netflix": "direct"},
        )
        == "mixed"
    )


def test_default_hydra_domains_join_the_ai_category() -> None:
    categories = build_routing_catalog(
        _catalog(),
        {"default": {"domains": ["openai.com"], "ips": []}},
    )

    ai = _category(categories, "ai")
    assert "local:default" in ai.source_keys
    assert ai.source_keys == ("local:default",)
    assert "HYDRA: default" in ai.sources


def test_operator_lists_get_their_own_category() -> None:
    categories = build_routing_catalog(
        _catalog(),
        {"bypass": {"domains": ["example.com"], "ips": []}},
    )

    local = _category(categories, "local")
    assert local.direction == ""
    assert local.source_keys == ("local:bypass",)


def test_category_menu_carries_the_current_destination() -> None:
    menu = category_menu(
        _catalog(),
        {"ext:youtube": "warp", "ext:netflix": "direct"},
        {},
    )

    media = next(item for item in menu if item["key"] == "media")
    assert media["target"] == "mixed"
    assert media["source_keys"] == ("ext:netflix", "ext:youtube")
    assert (media["routed"], media["total"]) == (2, 2)


def test_category_menu_counts_a_partially_routed_category() -> None:
    menu = category_menu(_catalog(), {"ext:youtube": "warp"}, {})

    media = next(item for item in menu if item["key"] == "media")
    assert media["target"] == "warp"
    assert (media["routed"], media["total"]) == (1, 2)

    media = next(item for item in menu if item["key"] == "media")
    assert media["note"] == ""


def test_reachability_lists_leave_the_russian_services_category() -> None:
    sources = {
        "category-ru": {
            "name": "Все российские сервисы",
            "url": "u",
            "desc": "Российские сервисы",
            "group": "ru",
        },
        "category-bank-ru": {
            "name": "Банки РФ",
            "url": "u",
            "desc": "Российские сервисы",
            "group": "ru",
        },
        "itDog-russia-inside": {
            "name": "Доступны только из РФ",
            "url": "u",
            "desc": "Российские сервисы",
            "group": "ru",
        },
        "itDog-russia-outside": {
            "name": "Недоступны из РФ",
            "url": "u",
            "desc": "Российские сервисы",
            "group": "ru",
        },
    }

    categories = build_routing_catalog(sources, {})

    assert categories == []


def test_cached_catalogue_drops_rollups_before_display_or_download(tmp_path: Path) -> None:
    cache = tmp_path / "catalog.json"
    cache.write_text(json.dumps({"sources": _catalog()}), encoding="utf-8")
    assert set(catalog.load_sources(cache)) == {"youtube", "netflix"}


def test_stale_aggregate_only_catalogue_needs_refresh(tmp_path: Path) -> None:
    from datetime import datetime

    cache = tmp_path / "catalog.json"
    cache.write_text(
        json.dumps({"updated_at": datetime.now().isoformat(), "sources": {"category-ai": _catalog()["category-ai"]}}),
        encoding="utf-8",
    )
    assert catalog.refresh_due(cache) is True
    cache.write_text(json.dumps({"updated_at": datetime.now().isoformat(), "sources": ["youtube"]}), encoding="utf-8")
    assert catalog.refresh_due(cache) is True


def test_catalogue_cache_falls_back_when_absent_or_malformed(tmp_path: Path) -> None:
    missing = catalog.load_sources(tmp_path / "absent.json")
    assert missing == {}  # no broad fallback; local defaults still work offline

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert catalog.load_sources(broken) == missing
    assert set(catalog.load_sources(broken, fallback=_catalog())) == {"youtube", "netflix"}

    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"sources": {}}), encoding="utf-8")
    assert catalog.load_sources(empty) == missing


def test_catalogue_cache_round_trips_through_a_refresh(tmp_path: Path) -> None:
    cache = tmp_path / "catalog.json"
    written: list[tuple] = []
    host = SimpleNamespace(
        atomic_write=lambda path, text, mode: written.append((path, text, mode)),
    )

    assert catalog.refresh_due(cache) is True
    with patch.object(
        catalog,
        "fetch_sources",
        return_value={"youtube": {"name": "YouTube", "url": "u", "desc": "d", "group": "media"}},
    ):
        ok, message = catalog.refresh_sources(cache, host=host)

    assert ok is True
    assert "1 источников" in message
    assert written[0][0] == cache
    assert written[0][2] == 0o600

    cache.write_text(written[0][1], encoding="utf-8")
    assert catalog.refresh_due(cache) is False
    assert catalog.load_sources(cache) == {
        "youtube": {"name": "YouTube", "url": "u", "desc": "d", "group": "media"},
    }


def test_catalogue_refresh_failure_is_reported_not_raised(tmp_path: Path) -> None:
    cache = tmp_path / "catalog.json"
    host = SimpleNamespace(atomic_write=lambda *args, **kwargs: None)

    with patch.object(catalog, "fetch_sources", side_effect=OSError("no network")):
        ok, message = catalog.refresh_sources(cache, host=host)

    assert ok is False
    assert "no network" in message
    assert catalog.load_sources(cache) == {}  # no broad fallback


def test_legacy_source_keys_are_renamed_and_kept_idempotent() -> None:
    raw = {
        "protocols": {
            "warp": {
                "config": {
                    "list_targets": {
                        "ext:russia": "direct",
                        "ext:geoblock": "warp",
                        "ext:google_ai": "warp",
                        "local:default": "warp",
                    },
                },
            },
        },
    }

    _normalize_warp_sources(raw)
    targets = raw["protocols"]["warp"]["config"]["list_targets"]

    assert targets == {
        "ext:category-ru": "direct",
        "ext:refilter": "warp",
        "ext:category-ai": "warp",
        "local:default": "warp",
    }
    _normalize_warp_sources(raw)
    assert targets == raw["protocols"]["warp"]["config"]["list_targets"]


def test_an_existing_catalogue_key_wins_over_the_legacy_one() -> None:
    raw = {
        "protocols": {
            "warp": {
                "config": {
                    "list_targets": {
                        "ext:russia": "warp",
                        "ext:category-ru": "direct",
                    },
                },
            },
        },
    }

    _normalize_warp_sources(raw)

    assert raw["protocols"]["warp"]["config"]["list_targets"] == {
        "ext:category-ru": "direct",
    }


def test_russian_service_category_does_not_claim_direct_is_a_russian_exit() -> None:
    categories = build_routing_catalog({"yandex": {"name": "Yandex", "group": "ru"}}, {})
    assert categories[0].direction == ""
    assert routing_catalog.DEFAULT_LOCAL_LIST == "default"
