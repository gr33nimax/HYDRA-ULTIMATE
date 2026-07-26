"""Compatibility facade for decomposed Telegram dashboard renderers."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.services.telegram import (
    dashboard_antidpi,
    dashboard_common,
    dashboard_fail2ban,
    dashboard_honeypot,
    dashboard_system,
)


def _mapping_projection(value: object) -> dict:
    return dashboard_common._mapping_projection(value)


def get_system_info_text(app: ApplicationService) -> str:
    return dashboard_system.get_system_info_text(app)


def get_antidpi_status_text(app: ApplicationService) -> str:
    return dashboard_antidpi.get_antidpi_status_text(app)


def get_fail2ban_status_text(app: ApplicationService) -> str:
    return dashboard_fail2ban.get_fail2ban_status_text(app)


def _format_period(seconds: object) -> str:
    return dashboard_common._format_period(seconds)


def get_antidpi_dashboard_text(app: ApplicationService) -> str:
    return dashboard_antidpi.get_antidpi_dashboard_text(app)


def _legacy_honeypot_status_text(app: ApplicationService) -> str:
    return dashboard_honeypot._legacy_honeypot_status_text(app)


def _parse_fail2ban_jail(detail: str) -> dict:
    return dashboard_fail2ban._parse_fail2ban_jail(detail)


def _legacy_fail2ban_dashboard_text(app: ApplicationService) -> str:
    return dashboard_fail2ban._legacy_fail2ban_dashboard_text(app)


def _format_security_timestamp(value: object) -> str:
    return dashboard_common._format_security_timestamp(value)


def _parse_fail2ban_ban_lines(
    lines: list[str],
    limit: int = 5,
) -> list[dict[str, str]]:
    return dashboard_common._parse_fail2ban_ban_lines(lines, limit)


def _recent_fail2ban_bans(
    app: ApplicationService,
    limit: int = 5,
) -> list[dict[str, str]]:
    return dashboard_fail2ban._recent_fail2ban_bans(app, limit)


def _lookup_security_intel(
    addresses: list[str],
) -> dict[str, dict[str, str]]:
    return dashboard_common._lookup_security_intel(addresses)


def _network_label(intel: dict[str, str]) -> str:
    return dashboard_common._network_label(intel)


def get_honeypot_status_text(app: ApplicationService) -> str:
    return dashboard_honeypot.get_honeypot_status_text(
        app,
        lookup_intel=_lookup_security_intel,
    )


def get_fail2ban_dashboard_text(app: ApplicationService) -> str:
    return dashboard_fail2ban.get_fail2ban_dashboard_text(
        app,
        recent_bans=_recent_fail2ban_bans,
        lookup_intel=_lookup_security_intel,
    )


__all__ = [
    "_format_period",
    "_format_security_timestamp",
    "_legacy_fail2ban_dashboard_text",
    "_legacy_honeypot_status_text",
    "_lookup_security_intel",
    "_network_label",
    "_parse_fail2ban_ban_lines",
    "_parse_fail2ban_jail",
    "get_antidpi_dashboard_text",
    "get_antidpi_status_text",
    "get_fail2ban_dashboard_text",
    "get_fail2ban_status_text",
    "get_honeypot_status_text",
    "get_system_info_text",
]
