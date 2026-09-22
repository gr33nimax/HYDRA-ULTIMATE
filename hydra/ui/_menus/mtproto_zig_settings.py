"""WEB-mode settings for mtproto.zig, kept out of the shared settings registry.

The shared registry imports this module, so the registry helpers are resolved at
call time: a module-level import would close the settings-registry cycle.
"""

from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui._menus.settings_support import FAILURE_TEXT, desired_state
from hydra.ui.tui import confirm, error, info, menu, prompt, success


def _configuration():
    from hydra.plugins.mtproto_zig import configuration

    return configuration


def _web_mode(desired: PluginState) -> str:
    return _configuration().web_mode(desired.config)


def option(desired: PluginState) -> tuple[str, str]:
    mode = _web_mode(desired)
    label = {
        "off": "выключен · только FakeTLS",
        "hybrid": "FakeTLS + WEB",
        "web-only": "только WEB",
    }.get(mode, mode)
    return "🌐 Режим WEB", label


def _report_change(changed: bool, success_text: str) -> None:
    if changed:
        success(success_text)
        return
    error(FAILURE_TEXT)


def open_menu(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    """Choose the WEB access mode through the transactional plugin command."""
    configuration = _configuration()
    while True:
        state = app.admin.load_state()
        desired = desired_state(state, "mtproto_zig")
        mode = _web_mode(desired)
        domain = configuration.web_domain(desired.config)
        choice = menu(
            [
                (
                    "1",
                    "🌐 Режим WEB",
                    f"{mode} · {domain}" if domain else mode,
                ),
                ("0", "↩ Назад", ""),
            ],
            "НАСТРОЙКИ MTPROTO ZIG",
        )
        if choice == "0":
            return
        if choice != "1":
            continue
        try:
            changed = _change_mode(state, desired, app, mode, domain)
        except (TypeError, ValueError) as exc:
            error(str(exc))
            prompt("Нажмите Enter")
            continue
        if changed is None:
            continue
        _report_change(changed, "Настройки WEB MTProto Zig обновлены")
        prompt("Нажмите Enter")


def _unchanged(configuration, target: str, mode: str, domain: str, chosen: str) -> bool:
    """True when the operator re-selected exactly what is already stored.

    The comparison uses the plugin's own hostname validation, so re-entering the
    same host with a trailing dot or different case stays a no-op instead of
    being reported as a failed change.
    """
    if target != mode:
        return False
    if target == "off":
        return True
    try:
        return configuration.normalize_web_domain(chosen) == domain
    except ValueError:
        return False


def _change_mode(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
    mode: str,
    domain: str,
) -> bool | None:
    """Return the command result, or ``None`` when the operator cancelled."""
    configuration = _configuration()
    selected = menu(
        [
            ("1", "Выключить WEB", "Останутся обычные FakeTLS-ссылки"),
            ("2", "FakeTLS + WEB", "Обе ссылки; WEB — Telegram Desktop 7.1+"),
            ("3", "Только WEB", "Прямые ссылки перестанут подключаться"),
            ("0", "Отмена", ""),
        ],
        f"РЕЖИМ WEB MTPROTO ZIG · сейчас {mode}",
    )
    target = {"1": "off", "2": "hybrid", "3": "web-only"}.get(selected)
    if target is None:
        return None
    new_domain = ""
    if target != "off":
        entered = prompt(
            "Домен WEB-релея (A-запись на этот сервер)",
            default=domain,
        ).strip()
        try:
            new_domain = configuration.normalize_web_domain(entered)
        except ValueError:
            # Let the command report the exact field error.
            new_domain = entered
        if domain and new_domain != domain:
            if not confirm(
                "Смена домена релея сделает нерабочими все выданные WEB-ссылки. Продолжить?",
                default=False,
            ):
                return None
    if target == "web-only" and mode != "web-only":
        if not confirm(
            "Прямые FakeTLS-ссылки перестанут подключаться: вход останется только через WEB. Переключить?",
            default=False,
        ):
            return None
    chosen = new_domain or domain
    if _unchanged(configuration, target, mode, domain, chosen):
        info(f"Режим WEB уже выбран: {target}")
        return None
    return app.plugin_command(
        state,
        "mtproto_zig",
        "set_web_settings",
        mode=target,
        domain=chosen,
        confirm_host_change=True,
    )


__all__ = ["open_menu", "option"]
