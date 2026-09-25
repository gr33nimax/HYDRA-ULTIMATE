from __future__ import annotations

from hydra.plugins.antidpi import normalization


RECORD = {"request": {"remote_ip": "198.51.100.7", "uri": "/.env"}}


def test_only_a_validated_cdn_socket_peer_is_suppressed():
    assert (
        normalization.normalize_vless_cdn_record(
            RECORD,
            is_cdn_peer=lambda address: address == "198.51.100.7",
        )
        is None
    )

    direct = normalization.normalize_vless_cdn_record(
        RECORD,
        is_cdn_peer=lambda _address: False,
    )
    assert direct is not None
    assert direct[0] == "198.51.100.7"


def test_a_missing_or_expired_prefix_cache_still_reports_the_scanner():
    """An unusable CDN cache must never grant the CDN exemption."""
    reported = normalization.normalize_vless_cdn_record(
        RECORD,
        is_cdn_peer=lambda _address: False,
    )

    assert reported is not None
    assert reported[1]["kind"] == "decoy_scan"
