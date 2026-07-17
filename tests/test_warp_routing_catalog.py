from hydra.plugins.warp.routing_catalog import build_routing_catalog, category_target
from hydra.plugins.warp.manager import _compact_destination_options
from hydra.core.state import PluginState


def test_catalog_merges_sources_by_user_category():
    bundle = {"rule_providers": [
        {"name": "twitter", "route_group": "Геоблок", "supported": True},
        {"name": "games", "route_group": "Геоблок", "supported": True},
        {"name": "EA", "route_group": "Игры", "supported": True},
        {"name": "private", "route_group": "DIRECT", "supported": False},
    ]}
    external = {
        "geoblock": {"name": "GEO-block", "desc": "built in"},
        "russia": {"name": "РФ-сервисы", "desc": "built in"},
    }

    categories = build_routing_catalog(bundle, external, {})
    by_key = {category.key: category for category in categories}

    assert by_key["geoblock"].label == "Обход блокировок"
    assert set(by_key["geoblock"].source_keys) == {
        "ext:geoblock", "yaml:twitter", "yaml:games",
    }
    assert by_key["games"].source_keys == ("yaml:EA",)
    assert by_key["ru_services"].source_keys == ("ext:russia",)
    assert all("yaml:private" not in category.source_keys for category in categories)


def test_category_target_reports_uniform_and_mixed_routes():
    category = build_routing_catalog(
        {"rule_providers": [
            {"name": "twitter", "route_group": "Геоблок", "supported": True},
        ]},
        {"geoblock": {"name": "GEO-block"}},
        {},
    )[0]
    assert category_target(category, {}) == "none"
    assert category_target(category, {
        "ext:geoblock": "warp_nl",
        "yaml:twitter": "warp_nl",
    }) == "warp_nl"
    assert category_target(category, {
        "ext:geoblock": "warp_nl",
        "yaml:twitter": "direct",
    }) == "mixed"


def test_default_hydra_domains_join_ai_category():
    categories = build_routing_catalog(None, {}, {"default": {"domains": ["openai.com"]}})
    assert len(categories) == 1
    assert categories[0].key == "ai"
    assert categories[0].label == "AI-сервисы"


def test_destination_menu_prioritises_selected_locations_without_duplicates():
    class Plugin:
        @staticmethod
        def available_destinations():
            return [
                ("direct", "direct"),
                ("warp_ultimate", "selector"),
                ("warp_ultimate_auto", "auto"),
                ("warp_ultimate_nl", "Netherlands"),
                ("warp_ultimate_ru", "Russia"),
                ("warp", "WGCF"),
            ]

    bundle = {"endpoints": [
        {"tag": "warp_ultimate_nl", "name": "Netherlands"},
        {"tag": "warp_ultimate_ru", "name": "Russia"},
    ]}
    ps = PluginState(config={
        "ultimate_selected_tag": "warp_ultimate_nl",
        "ultimate_route_tags": ["warp_ultimate_nl", "warp_ultimate_ru"],
    })

    options = _compact_destination_options(Plugin(), ps, bundle)
    assert [tag for tag, _label in options] == [
        "direct", "warp_ultimate_auto", "warp_ultimate_nl", "warp_ultimate_ru", "warp",
    ]
    assert "Netherlands" in options[2][1]
