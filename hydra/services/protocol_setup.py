"""Application preflight for protocol activation."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from hydra.contracts import JsonValue
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.base import BasePlugin, PluginCapabilities


class CertificateProvider(Protocol):
    def ensure(
        self,
        domain: str,
        config: dict,
    ) -> tuple[str, str]: ...


def normalize_protocol_config(
    config: Mapping[str, JsonValue],
    defaults: tuple[tuple[str, JsonValue], ...] = (),
) -> dict[str, JsonValue]:
    """Return normalized desired config without mutating the caller's value."""
    normalized = copy.deepcopy(dict(config))
    for key, value in defaults:
        normalized.setdefault(key, copy.deepcopy(value))
    return normalized


def _requires_tls_domain(plugin: BasePlugin, state: AppState) -> bool:
    """Ask the plugin whether this desired state still needs a certificate."""
    hook = getattr(plugin, "needs_tls_domain", None)
    if not callable(hook):
        return True
    return bool(hook(state))


def _additional_certificate_requirements(
    plugin: BasePlugin,
    state: AppState,
) -> tuple[tuple[str, str, str], ...]:
    """Read one optional plugin-owned extra certificate requirement.

    A transport may serve TLS without owning a certificate for its main domain
    and still need a real one for a second name, for example a WEB relay host.
    """
    hook = getattr(plugin, "certificate_requirements", None)
    if not callable(hook):
        return ()
    declared = hook(state)
    if not isinstance(declared, (list, tuple)):
        return ()
    return tuple(
        (str(entry[0]), str(entry[1]), str(entry[2]))
        for entry in declared
        if isinstance(entry, (list, tuple)) and len(entry) == 3
    )


def normalize_required_domain(value: object) -> str:
    """Normalize a required TLS host or reject adapter input early."""
    normalized = str(value or "").strip().lower().rstrip(".")
    if not normalized or "://" in normalized or any(character.isspace() for character in normalized):
        raise ValueError("Некорректный домен")
    return normalized


@dataclass(frozen=True)
class ProtocolSetupService:
    """Complete non-interactive prerequisites before a lifecycle hook runs."""

    certificates: CertificateProvider
    get_plugin: Callable[[str], BasePlugin | None]

    def stage_domain(self, state: AppState, name: str, domain: object) -> str:
        """Validate and stage an explicit TLS domain in desired state."""
        plugin = self.get_plugin(name)
        if plugin is None:
            raise LookupError(f"Неизвестный протокол: {name}")
        capabilities = getattr(plugin.meta, "capabilities", None)
        if not isinstance(capabilities, PluginCapabilities):
            raise ValueError(f"Протокол {name} не поддерживает TLS-домен")
        source = capabilities.tls_domain_source
        if source not in {"network", "protocol"}:
            raise ValueError(f"Протокол {name} не поддерживает TLS-домен")

        normalized = normalize_required_domain(domain)
        if source == "network":
            state.network.domain = normalized
            return normalized

        protocol = state.protocols.setdefault(name, PluginState())
        protocol.config["domain"] = normalized
        return normalized

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
        if source and not _requires_tls_domain(plugin, state):
            # A plugin may serve TLS without owning a certificate, for example
            # with a borrowed Reality handshake.
            source = ""
        protocol = state.protocols.get(name)
        if protocol is None:
            raise ValueError(f"Конфигурация {name} отсутствует")
        protocol.config = normalize_protocol_config(
            protocol.config,
            defaults,
        )
        if not source:
            self._apply_additional_certificates(plugin, state, protocol)
            return
        domain = state.network.domain if source == "network" else protocol.config.get("domain", "")
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

    def prepare_enabled(self, state: AppState) -> None:
        """Refresh prerequisites for every enabled protocol before apply."""
        for name, protocol in sorted(state.protocols.items()):
            if protocol.enabled and self.get_plugin(name) is not None:
                self.prepare_enable(state, name)

    def _apply_additional_certificates(
        self,
        plugin: BasePlugin,
        state: AppState,
        protocol: PluginState,
    ) -> None:
        """Obtain every extra certificate the plugin declares, fail-closed."""
        for domain, cert_key, key_key in _additional_certificate_requirements(
            plugin,
            state,
        ):
            normalized = normalize_required_domain(domain)
            cert, key = self.certificates.ensure(normalized, protocol.config)
            protocol.config[cert_key] = cert
            protocol.config[key_key] = key


__all__ = [
    "CertificateProvider",
    "ProtocolSetupService",
    "normalize_protocol_config",
    "normalize_required_domain",
]
