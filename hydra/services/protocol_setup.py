"""Application preflight for protocol activation."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin, PluginCapabilities


class CertificateProvider(Protocol):
    def ensure(
        self,
        domain: str,
        config: dict,
    ) -> tuple[str, str]: ...


def normalize_protocol_config(
    config: Mapping[str, object],
    defaults: tuple[tuple[str, object], ...] = (),
) -> dict[str, object]:
    """Return normalized desired config without mutating the caller's value."""
    normalized = copy.deepcopy(dict(config))
    for key, value in defaults:
        normalized.setdefault(key, value)
    return normalized


def normalize_required_domain(value: object) -> str:
    """Normalize a required TLS host or reject adapter input early."""
    normalized = str(value or "").strip().lower().rstrip(".")
    if (
        not normalized
        or "://" in normalized
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError("Некорректный домен")
    return normalized


@dataclass(frozen=True)
class ProtocolSetupService:
    """Complete non-interactive prerequisites before a lifecycle hook runs."""

    certificates: CertificateProvider
    get_plugin: Callable[[str], BasePlugin | None]

    def prepare_enable(self, state: AppState, name: str) -> None:
        plugin = self.get_plugin(name)
        if plugin is None:
            raise LookupError(f"Неизвестный протокол: {name}")
        capabilities = getattr(plugin.meta, "capabilities", None)
        if not isinstance(capabilities, PluginCapabilities):
            return
        source = capabilities.tls_domain_source
        defaults = capabilities.config_defaults
        if not source and not defaults:
            return
        protocol = state.protocols.get(name)
        if protocol is None:
            raise ValueError(f"Конфигурация {name} отсутствует")
        protocol.config = normalize_protocol_config(
            protocol.config,
            defaults,
        )
        if not source:
            return
        domain = (
            state.network.domain
            if source == "network"
            else protocol.config.get("domain", "")
        )
        try:
            normalized = normalize_required_domain(domain)
        except ValueError:
            raise ValueError(f"Корректный домен обязателен для {name}")
        cert, key = self.certificates.ensure(normalized, protocol.config)
        protocol.config.update(
            {
                "cert_file": cert,
                "key_file": key,
            },
        )
        if source == "protocol":
            protocol.config["domain"] = normalized


__all__ = [
    "CertificateProvider",
    "ProtocolSetupService",
    "normalize_protocol_config",
    "normalize_required_domain",
]
