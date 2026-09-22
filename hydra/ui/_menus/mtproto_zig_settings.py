"""WEB-mode settings for mtproto.zig, kept out of the shared settings registry.

The shared registry imports this module, so the registry helpers are resolved at
call time: a module-level import would close the settings-registry cycle.
"""

from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui._menus.settings_support import desired_state, report_change
from hydra.ui.tui import confirm, error, info, menu, prompt, success

_MODE_LABELS = {
    "off": "выключен · только FakeTLS",
    "hybrid": "FakeTLS + WEB",
    "web-only": "только WEB",
}


def _configuration():
    from hydra.plugins.mtproto_zig import configuration

    return configuration


def _web_mode(desired: PluginState) -> str:
    return _configuration().web_mode(desired.config)


def _mode_label(mode: str) -> str:
    return _MODE_LABELS.get(mode, mode)


def _cover_domain(desired: PluginState) -> str:
    return str(desired.config.get("domain", "")).strip().lower().rstrip(".")


def option(desired: PluginState) -> tuple[str, str]:
    cover = _cover_domain(desired) or "не задан"
    return "⚙️ Настройки MTProto Zig", f"WEB: {_mode_label(_web_mode(desired))} · FakeTLS: {cover}"


def _report_change(app: ApplicationService, changed: bool, success_text: str) -> None:
    report_change(app, changed, success_text, report_success=success, report_error=error)


def open_menu(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    """Open the two independent settings: WEB access mode and FakeTLS cover.

    The protocol menu shows this adapter once, so the rows here are the two
    values R16 keeps separate. Selecting a row opens its chooser or prompt
    directly: no intermediate menu repeats the row that was pressed.
    """
    desired = desired_state(state, "mtproto_zig")
    selected = menu(
        [
            ("1", "🌐 Режим WEB", _mode_label(_web_mode(desired))),
            ("2", "🔒 Домен FakeTLS", _cover_domain(desired) or "не задан"),
            ("0", "↩ Назад", ""),
        ],
        "НАСТРОЙКИ MTPROTO ZIG",
    )
    if selected == "1":
        _open_web_mode(state, desired, app)
    elif selected == "2":
        _open_cover_domain(state, desired, app)


def _open_web_mode(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> None:
    """Choose the WEB access mode through the transactional plugin command.

    ``None`` from :func:`_change_mode` means the operator cancelled or re-picked
    the current mode, which ends the interaction instead of redrawing a menu.
    """
    configuration = _configuration()
    mode = _web_mode(desired)
    domain = configuration.web_domain(desired.config)
    try:
        changed = _change_mode(state, desired, app, mode, domain)
    except (TypeError, ValueError) as exc:
        error(str(exc))
        prompt("Нажмите Enter")
        return
    if changed is None:
        return
    _report_change(app, changed, "Настройки WEB MTProto Zig обновлены")
    prompt("Нажмите Enter")


def _open_cover_domain(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> None:
    """Change the FakeTLS cover domain through the transactional command.

    The domain is embedded in every issued FakeTLS secret, so a real change is
    confirmed before the command runs. Validation refuses the value before that
    prompt, so an empty or IP-literal domain never reaches the mutation.
    """
    configuration = _configuration()
    current = _cover_domain(desired)
    entered = prompt(
        "Домен FakeTLS (чужой сайт для FakeTLS-handshake)",
        default=current,
    ).strip()
    try:
        chosen = configuration.normalize_cover_domain(entered)
    except ValueError as exc:
        error(str(exc))
        prompt("Нажмите Enter")
        return
    if chosen == current:
        info(f"Домен FakeTLS уже задан: {chosen}")
        return
    if current and not confirm(
        "Смена домена FakeTLS сделает нерабочими все выданные FakeTLS-ссылки: "
        "домен вшит в секрет (ee<secret><domain hex>). Продолжить?",
        default=False,
    ):
        return
    try:
        changed = app.plugin_command(
            state,
            "mtproto_zig",
            "set_domain",
            domain=chosen,
            confirm_change=True,
        )
    except (TypeError, ValueError) as exc:
        error(str(exc))
        prompt("Нажмите Enter")
        return
    _report_change(app, changed, f"Домен FakeTLS изменён на {chosen}")
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
    """Return the command result, or ``None`` when cancelled or unchanged."""
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
