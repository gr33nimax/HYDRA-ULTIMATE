from __future__ import annotations

from hydra.plugins.antidpi.normalization import normalize_vless_cdn_record


RECORD = {"request": {"remote_ip": "198.51.100.7", "uri": "/.env"}}


def test_only_a_validated_cdn_socket_peer_is_suppressed():
    assert normalize_vless_cdn_record(RECORD, is_cdn_peer=lambda address: address == "198.51.100.7") is None

    direct = normalize_vless_cdn_record(RECORD, is_cdn_peer=lambda _address: False)
    assert direct is not None
    assert direct[0] == "198.51.100.7"
