from __future__ import annotations

from hydra.core.singbox_config import (
    default_dns_config,
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
