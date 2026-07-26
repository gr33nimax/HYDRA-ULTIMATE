"""Telegram network update orchestration."""
from __future__ import annotations

import threading
from collections.abc import Callable

from .tg_nets_model import (
    BUILTIN_NETS,
    HTTP_TIMEOUT,
    TG_ASNS,
    dedup,
    in_telegram_space,
    remove_more_specific,
)

Source = Callable[[list[int]], tuple[list[str], int, str]]


def fetch(
    sources: list[tuple[str, Source]],
) -> tuple[list[str], list[str], dict]:
    results: dict[str, tuple[list[str], int, str]] = {}

    def run_source(name: str, source: Source) -> None:
        try:
            results[name] = source(TG_ASNS)
        except Exception:
            results[name] = ([], 0, "ошибка")

    threads = [
        threading.Thread(target=run_source, args=item, daemon=True)
        for item in sources
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=HTTP_TIMEOUT + 10)
    raw: list[str] = []
    used: list[str] = []
    stats: dict = {}
    for name, _ in sources:
        networks, count, message = results.get(
            name,
            ([], 0, "нет ответа"),
        )
        stats[name] = (count, message)
        if networks:
            raw.extend(networks)
            used.append(name)
    raw = [network for network in raw if in_telegram_space(network)]
    anchors_added = 0
    for anchor in BUILTIN_NETS:
        if anchor not in raw:
            raw.append(anchor)
            anchors_added += 1
    raw_count = len(dedup(raw))
    final = remove_more_specific(dedup(raw) if used else list(BUILTIN_NETS))
    stats.update(
        _anchors_added=anchors_added,
        _raw_count=raw_count,
        _removed=raw_count - len(final),
    )
    return final, used, stats
