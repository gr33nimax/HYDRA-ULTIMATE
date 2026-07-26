"""Interactive activation prerequisites shared by protocol menu controllers."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.services.protocol_setup import normalize_required_domain


Message = Callable[[str], None]
Prompt = Callable[..., str]


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


def _save_domain(
    state: AppState,
    plugin_name: str,
    source: str,
    domain: str,
) -> None:
    if source == "network":
        state.network.domain = domain
        return
    protocol = state.protocols.setdefault(plugin_name, PluginState())
    protocol.config["domain"] = domain


def _prepare_certificate_domain(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    ask: Prompt,
    report_error: Message,
) -> bool:
    source = _domain_source(plugin)
    if not source:
        return True

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
            return False

    _save_domain(state, name, source, normalized)
    app.admin.save_state(state)
    return True


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


def prepare_interactive_activation(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    ask: Prompt,
    report_error: Message,
) -> bool:
    """Collect every mandatory TLS value before lifecycle side effects."""
    if not _prepare_certificate_domain(
        state,
        plugin,
        app,
        ask=ask,
        report_error=report_error,
    ):
        return False
    return _prepare_shadowtls_sni(
        state,
        plugin,
        app,
        report_error=report_error,
    )


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

        if not prepare_interactive_activation(
            state,
            plugin,
            app,
            ask=ask,
            report_error=report_error,
        ):
            return

        if not desired.installed:
            report_info("Установка...")
            if not app.protocols.install(state, name):
                report_error("Ошибка установки")
                return

        if app.protocols.enable(state, name):
            message = (
                "Протокол установлен, включён и применён"
                if not desired.installed
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
    "prepare_interactive_activation",
    "run_lifecycle_action",
]
