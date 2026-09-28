from __future__ import annotations

from hydra.core.singbox_config import (
    DEFAULT_DNS_STRATEGY,
    default_dns_config,
    dns_policy,
    generate_config,
    migrate_legacy_default_dns,
)


def _legacy_default_config() -> dict:
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://dns.quad9.net/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "detour": "direct",
                },
                {
                    "tag": "dns-direct",
                    "address": "1.1.1.1",
                    "detour": "direct",
                },
            ],
            "rules": [],
        },
    }


def test_default_dns_uses_modern_server_schema() -> None:
    dns = default_dns_config()

    assert dns == {
        "servers": [
            {
                "type": "https",
                "tag": "dns-remote",
                "server": "dns.quad9.net",
                "domain_resolver": "dns-direct",
            },
            {
                "type": "udp",
                "tag": "dns-direct",
                "server": "1.1.1.1",
            },
        ],
        "rules": [],
        "strategy": "ipv4_only",
    }
    assert all("address" not in server for server in dns["servers"])
    assert all("address_resolver" not in server for server in dns["servers"])


def test_migrate_legacy_default_dns_preserves_the_source_document() -> None:
    source = _legacy_default_config()

    migrated, changed = migrate_legacy_default_dns(source)

    assert changed is True
    assert source == _legacy_default_config()
    assert migrated["log"] == source["log"]
    assert migrated["dns"] == default_dns_config()


def test_migrate_legacy_default_dns_ignores_plugin_owned_dns() -> None:
    source = {
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dnscrypt-local",
                    "server": "127.0.0.1",
                    "server_port": 5300,
                },
            ],
        },
    }

    migrated, changed = migrate_legacy_default_dns(source)

    assert changed is False
    assert migrated is source


# ── Стратегия резолва не теряется при чужом dns-фрагменте ──────────────


def test_plugin_dns_keeps_the_resolution_strategy() -> None:
    # Ровно то, что отдаёт dnscrypt на боевом сервере: свои серверы, без стратегии.
    # Раньше такой фрагмент подменял дефолт целиком, и на машине без IPv6 ядро висело
    # на v6-адресах десятками секунд, прежде чем упасть на IPv4.
    plugin_dns = {
        "servers": [
            {
                "type": "udp",
                "tag": "dnscrypt-local",
                "server": "127.0.0.1",
                "server_port": 5300,
            },
        ],
        "rules": [],
    }

    policy = dns_policy(plugin_dns)

    assert policy["strategy"] == DEFAULT_DNS_STRATEGY
    assert policy["servers"] == plugin_dns["servers"], "серверы остаются плагинные"
    assert plugin_dns.get("strategy") is None, "входной документ не меняется"


def test_plugin_dns_may_choose_its_own_strategy() -> None:
    policy = dns_policy({"servers": [], "rules": [], "strategy": "prefer_ipv4"})

    assert policy["strategy"] == "prefer_ipv4"


def test_without_a_plugin_dns_the_default_policy_is_used() -> None:
    assert dns_policy(None) == default_dns_config()
    assert dns_policy({}) == default_dns_config()


def test_generate_config_keeps_the_strategy_with_a_plugin_dns() -> None:
    # Замок на самом месте сборки: стратегия терялась не в dns_policy, а в generate_config.
    from hydra.contracts import ConfigFragment
    from hydra.core.state_models import AppState

    config = generate_config(
        AppState(),
        {"dnscrypt": ConfigFragment(dns={"servers": [{"tag": "dnscrypt-local"}], "rules": []})},
    )

    assert config["dns"]["strategy"] == DEFAULT_DNS_STRATEGY
    assert config["dns"]["servers"] == [{"tag": "dnscrypt-local"}]


def test_route_declares_a_default_domain_resolver_for_the_1_14_kernel() -> None:
    # sing-box 1.14 (HydraCore) removed the deprecated missing-domain-resolver
    # fallback that the ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER env only masks
    # on older kernels. Without route.default_domain_resolver the candidate
    # rejects the active config and the extended->hydracore switch is impossible.
    from hydra.core.state_models import AppState

    config = generate_config(AppState(), {})
    resolver = config["route"]["default_domain_resolver"]
    tags = {server["tag"] for server in config["dns"]["servers"]}
    assert resolver in tags
    # A leaf resolver (no onward domain_resolver) avoids a bootstrap loop.
    assert resolver == "dns-direct"


def test_default_domain_resolver_follows_a_plugin_dns_server() -> None:
    from hydra.contracts import ConfigFragment
    from hydra.core.state_models import AppState

    config = generate_config(
        AppState(),
        {"dnscrypt": ConfigFragment(dns={"servers": [{"tag": "dnscrypt-local"}], "rules": []})},
    )

    assert config["route"]["default_domain_resolver"] == "dnscrypt-local"
