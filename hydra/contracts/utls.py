"""Единый список uTLS-отпечатков для клиентских профилей.

Живёт в contracts, потому что его спрашивают разные протоколы: прямой VLESS
(Reality/XHTTP) и VLESS через CDN. Плагины зависят от contracts, contracts от
плагинов — нет.
"""

from __future__ import annotations

UTLS_FINGERPRINTS = (
    "none",
    "chrome",
    "firefox",
    "safari",
    "edge",
    "ios",
    "android",
    "random",
    "randomized",
)


def validate_fingerprint(value: object) -> str:
    """Вернуть поддерживаемый uTLS-отпечаток в нижнем регистре."""
    fingerprint = str(value or "").strip().lower()
    if fingerprint not in UTLS_FINGERPRINTS:
        allowed = ", ".join(UTLS_FINGERPRINTS)
        raise ValueError(f"utls_fingerprint must be one of: {allowed}")
    return fingerprint


__all__ = ["UTLS_FINGERPRINTS", "validate_fingerprint"]
