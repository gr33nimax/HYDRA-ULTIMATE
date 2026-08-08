"""Interactive activation prerequisites shared by protocol menu controllers."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.services.protocol_setup import normalize_required_domain


Message = Callable[[str], None]
Prompt = Callable[..., str]
ThemeChooser = Callable[[str], str]


@dataclass(frozen=True)
class ActivationPreparation:
    """Validated values staged for one atomic lifecycle activation."""

    domain: str | None = None


def _domain_source(plugin: object) -> str:
    capabilities = getattr(getattr(plugin, "meta", None), "capabilities", None)
    return str(getattr(capabilities, "tls_domain_source", "") or "")


def _configured_domain(
    state: AppState,
    plugin_name: str,
    source: str,
) -> object:
    if source == "network":
        return state.network.domain
    protocol = state.protocols.get(plugin_name)
    return protocol.config.get("domain", "") if protocol else ""


def _prepare_certificate_domain(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    ask: Prompt,
    report_error: Message,
) -> ActivationPreparation | None:
    source = _domain_source(plugin)
    if not source:
        return ActivationPreparation()

    name = plugin.meta.name
    current = _configured_domain(state, name, source)
    try:
        normalized = normalize_required_domain(current)
    except ValueError:
        label = plugin.meta.display_name or name
        entered = ask(
            f"Введите домен для {label}",
            default=str(current or ""),
        )
        try:
            normalized = normalize_required_domain(entered)
        except ValueError:
            report_error(
                f"Для {label} нужен корректный домен без схемы и пробелов",
            )
            return None

    return ActivationPreparation(domain=normalized)


def _prepare_shadowtls_sni(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    report_error: Message,
) -> bool:
    if plugin.meta.name != "shadowtls":
        return True
    protocol = state.protocols.setdefault("shadowtls", PluginState())
    if str(protocol.config.get("handshake_sni", "")).strip():
        return True

    from hydra.ui._menus.shadowtls_settings import choose_shadowtls_sni

    value = choose_shadowtls_sni()
    if not value:
        report_error("Для ShadowTLS необходимо выбрать сторонний TLS 1.3 SNI")
        return False
    if not app.plugin_command(
        state,
        "shadowtls",
        "set_handshake_sni",
        value=value,
    ):
        report_error("Не удалось сохранить SNI ShadowTLS")
        return False
    return True


def _prepare_decoy_theme(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    choose: ThemeChooser | None,
) -> bool:
    """Record the decoy site once, asking only in interactive adapters."""
    from hydra.plugins.decoy_support import (
        DECOY_THEME_KEY,
        supports_decoy_theme,
    )

    if choose is None or not supports_decoy_theme(plugin):
        return True
    name = plugin.meta.name
    protocol = state.protocols.setdefault(name, PluginState())
    if str(protocol.config.get(DECOY_THEME_KEY, "")).strip():
        return True

    from hydra.ui._menus.decoy_theme import current_theme

    selected = choose(current_theme(plugin, protocol))
    if not selected:
        return True
    protocol.config[DECOY_THEME_KEY] = selected
    app.admin.save_state(state)
    return True


def prepare_interactive_activation(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    ask: Prompt,
    report_error: Message,
    choose_decoy: ThemeChooser | None = None,
) -> ActivationPreparation | None:
    """Collect every mandatory TLS value before lifecycle side effects."""
    preparation = _prepare_certificate_domain(
        state,
        plugin,
        app,
        ask=ask,
        report_error=report_error,
    )
    if preparation is None:
        return None
    if not _prepare_shadowtls_sni(
        state,
        plugin,
        app,
        report_error=report_error,
    ):
        return None
    if not _prepare_decoy_theme(state, plugin, app, choose_decoy):
        return None
    return preparation


def run_lifecycle_action(
    state: AppState,
    plugin: object,
    desired: PluginState,
    app: ApplicationService,
    *,
    ask: Prompt,
    report_error: Message,
    report_info: Message,
    report_success: Message,
    pause: Prompt,
    choose_decoy: ThemeChooser | None = None,
) -> None:
    """Install/enable/disable a protocol without leaking failures to the root."""
    name = plugin.meta.name
    try:
        if desired.enabled:
            if app.protocols.disable(state, name):
                report_success("Протокол выключен")
            else:
                report_error(app.apply_error() or "Ошибка выключения протокола")
            return

        preparation = prepare_interactive_activation(
            state,
            plugin,
            app,
            ask=ask,
            report_error=report_error,
            choose_decoy=choose_decoy,
        )
        if preparation is None:
            return

        was_installed = desired.installed
        if not was_installed:
            report_info("Установка...")

        if app.protocols.activate(
            state,
            name,
            domain=preparation.domain,
        ):
            message = (
                "Протокол установлен, включён и применён"
                if not was_installed
                else "Протокол включён"
            )
            report_success(message)
        else:
            report_error(app.apply_error() or "Ошибка применения конфигурации")
    except Exception as exc:
        report_error(f"Ошибка настройки или активации {name}: {exc}")
    finally:
        pause("Нажмите Enter")


__all__ = [
    "ActivationPreparation",
    "prepare_interactive_activation",
    "run_lifecycle_action",
]
