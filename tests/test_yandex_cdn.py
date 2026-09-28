from __future__ import annotations

from hydra.core.yandex_cdn import CACHE_TTL, contains_peer, refresh_prefixes


def test_a_fresh_validated_yandex_prefix_allows_only_its_socket_peer(tmp_path):
    cache = tmp_path / "prefixes.json"

    outcome = refresh_prefixes(
        cache_file=cache,
        now=100,
        fetch=lambda: b'{"prefixes":["198.51.100.0/24"]}',
    )

    assert outcome.ok
    assert contains_peer("198.51.100.7", cache_file=cache, now=101)
    assert not contains_peer("203.0.113.7", cache_file=cache, now=101)


def test_invalid_or_expired_prefix_data_fails_closed(tmp_path):
    cache = tmp_path / "prefixes.json"
    refresh_prefixes(
        cache_file=cache,
        now=100,
        fetch=lambda: b'{"prefixes":["198.51.100.0/24"]}',
    )

    outcome = refresh_prefixes(
        cache_file=cache,
        now=101,
        fetch=lambda: b'{"prefixes":["not-a-network"]}',
    )

    assert not outcome.ok
    assert outcome.error
    assert contains_peer("198.51.100.7", cache_file=cache, now=101)
    assert not contains_peer("198.51.100.7", cache_file=cache, now=100 + CACHE_TTL + 1)
