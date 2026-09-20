"""Read-only classification of persisted legacy Telemt settings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

_COMPATIBLE_KEYS = frozenset(
    {
        "advanced",
        "ipv4",
        "ipv6",
        "network",
        "port",
        "settings_version",
        "tls_domain",
        "use_middle_proxy",
    }
)
_OPTIONAL_LEGACY_KEYS = frozenset(
    {
        "client_mss",
        "fallback_cfg",
        "ios_fix_enabled",
        "singbox_integration_enabled",
        "syn_limiter_enabled",
        "singbox_integration_port",
    }
)


@dataclass(frozen=True)
class MigrationPreview:
    blockers: tuple[str, ...]

    @property
    def is_compatible(self) -> bool:
        return not self.blockers


def preview(config: Mapping[str, object]) -> MigrationPreview:
    """Report legacy options the new core cannot safely apply or erase."""
    blockers = []
    for key in sorted(config):
        value = config[key]
        if key in _COMPATIBLE_KEYS:
            continue
        if key in _OPTIONAL_LEGACY_KEYS and not value:
            continue
        blockers.append(key)
    return MigrationPreview(tuple(blockers))
