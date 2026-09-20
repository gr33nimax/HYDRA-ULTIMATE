"""Legacy Telemt state is classified before the new core touches it."""

from hydra.plugins.telemt import migration


def test_legacy_core_settings_are_mappable():
    result = migration.preview(
        {
            "port": 8443,
            "tls_domain": "mask.example",
            "ipv4": True,
            "ipv6": False,
            "use_middle_proxy": True,
        }
    )

    assert result.is_compatible
    assert result.blockers == ()


def test_legacy_side_effect_features_block_migration():
    result = migration.preview(
        {
            "port": 8443,
            "tls_domain": "mask.example",
            "client_mss": "1200",
            "fallback_cfg": {"enabled": True},
            "ios_fix_enabled": True,
            "singbox_integration_enabled": True,
            "syn_limiter_enabled": True,
        }
    )

    assert not result.is_compatible
    assert result.blockers == (
        "client_mss",
        "fallback_cfg",
        "ios_fix_enabled",
        "singbox_integration_enabled",
        "syn_limiter_enabled",
    )


def test_unknown_legacy_option_is_not_silently_ignored():
    result = migration.preview({"tls_domain": "mask.example", "invented": True})

    assert result.blockers == ("invented",)
