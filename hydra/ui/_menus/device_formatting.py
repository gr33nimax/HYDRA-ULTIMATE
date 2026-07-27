"""Shared presentation helpers for registered and live devices."""
from __future__ import annotations

from hydra.services.subscriptions.devices import NETWORK_SOURCE


ADDRESS_WIDTH = 30
_LOOPBACK = frozenset(("127.0.0.1", "::1", "::ffff:127.0.0.1"))


def address_label(address: str) -> str:
    """Explain an internal proxy hop instead of presenting it as a device."""
    if address in _LOOPBACK:
        return "адрес скрыт мультиплексором"
    if not address:
        return "адрес неизвестен"
    if len(address) <= ADDRESS_WIDTH:
        return address
    return f"{address[:ADDRESS_WIDTH - 1]}…"


def source_label(source: str, user_agent: str = "") -> str:
    """Describe the quality of a subscription device identifier."""
    if not source:
        return "неизвестно"
    if source == NETWORK_SOURCE:
        return (
            "по клиенту (без HWID)"
            if user_agent.strip()
            else "по адресу (без HWID)"
        )
    return source


__all__ = ["address_label", "source_label"]
