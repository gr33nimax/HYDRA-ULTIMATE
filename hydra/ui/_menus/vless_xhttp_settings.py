"""TUI adapter for VLESS/XHTTP desired settings."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.vless_xhttp import presets, tuning
from hydra.services.application import ApplicationService
from hydra.ui._menus.decoy_theme import open_decoy_menu, theme_label
from hydra.ui._menus.vless_xhttp_tuning import open_menu as open_tuning_menu
from hydra.ui.tui import error, menu, prompt, success


def option(_desired: PluginState) -> tuple[str, str]:
    return "⚙️  Настройки", "Домен, путь, режим и профиль XHTTP"


def _summary(config: dict) -> tuple[str, str]:
    """Return the preset label and tuning summary of a desired config."""
    try:
        return (
            presets.preset_label(presets.current_preset(config)),
            tuning.summary(config),
        )
    except ValueError as exc:
        return "🛠 Пользовательский", str(exc)


def open_menu(
    state: AppState,
    plugin: object,
    app: ApplicationService,
) -> None:
    while True:
        state = app.admin.load_state()
        desired = state.protocols.get("vless") or PluginState()
        domain = str(desired.config.get("domain", ""))
        path = str(desired.config.get("xhttp_path", "/xhttp"))
        mode = str(desired.config.get("xhttp_mode", "stream-up"))
        preset_label, tuning_summary = _summary(desired.config)
        fingerprint = str(desired.config.get("utls_fingerprint", "none"))
        decoy = str(desired.config.get("decoy_theme", "media"))
        choice = menu(
            [
                ("1", "Домен", domain or "не настроен"),
                ("2", "XHTTP path", path),
                ("3", "XHTTP mode", mode),
                ("4", "Профиль транспорта", preset_label),
                ("5", "Тонкая настройка", tuning_summary),
                ("6", "uTLS-отпечаток клиента", fingerprint),
                ("7", "Сайт-заглушка", theme_label(decoy)),
                ("0", "← Назад", ""),
            ],
            "НАСТРОЙКИ VLESS + XHTTP",
        )
        if choice == "0":
            return
        try:
            changed = _change(choice, state, desired, plugin, app)
            if changed is None:
                continue
            if changed:
                success("Настройки VLESS + XHTTP обновлены")
            else:
                error("Не удалось применить настройки VLESS + XHTTP")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _change(
    choice: str,
    state: AppState,
    desired: PluginState,
    plugin: object,
    app: ApplicationService,
) -> bool | None:
    if choice == "1":
        value = prompt(
            "Новый домен VLESS + XHTTP",
            default=str(desired.config.get("domain", "")),
        )
        if not value:
            return None
        return app.plugin_command(
            state,
            "vless",
            "set_domain",
            domain=value,
        )
    if choice == "2":
        value = prompt(
            "Новый XHTTP path",
            default=str(desired.config.get("xhttp_path", "/xhttp")),
        )
        return app.plugin_command(
            state,
            "vless",
            "set_path",
            path=value,
        )
    if choice == "3":
        selected = menu(
            [
                ("1", "stream-up", "рекомендуемый"),
                ("2", "packet-up", "пакетная загрузка"),
                ("3", "stream-one", "один поток"),
                ("0", "Отмена", ""),
            ],
            "РЕЖИМ XHTTP",
        )
        mode = {
            "1": "stream-up",
            "2": "packet-up",
            "3": "stream-one",
        }.get(selected)
        if mode is None:
            return None
        return app.plugin_command(
            state,
            "vless",
            "set_mode",
            mode=mode,
        )
    if choice == "4":
        return _change_preset(state, app)
    if choice == "5":
        open_tuning_menu(state, app)
        return None
    if choice == "6":
        return _change_fingerprint(state, desired, app)
    if choice == "7":
        open_decoy_menu(state, plugin, app)
        return None
    return None


def _change_fingerprint(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> bool | None:
    from hydra.plugins.vless_xhttp.tuning import UTLS_FINGERPRINTS

    current = str(desired.config.get("utls_fingerprint", "none"))
    options = [
        (
            str(index),
            name + (" ·" if name == current else ""),
            "как у браузера" if name not in {"random", "randomized"} else "случайный",
        )
        for index, name in enumerate(UTLS_FINGERPRINTS, start=1)
    ]
    selected = menu(
        [*options, ("0", "Отмена", "")],
        "uTLS-ОТПЕЧАТОК КЛИЕНТА",
    )
    if not selected.isdigit() or selected == "0":
        return None
    index = int(selected) - 1
    if not 0 <= index < len(UTLS_FINGERPRINTS):
        return None
    return app.plugin_command(
        state,
        "vless",
        "set_tuning",
        utls_fingerprint=UTLS_FINGERPRINTS[index],
    )


def _change_preset(
    state: AppState,
    app: ApplicationService,
) -> bool | None:
    names = sorted(presets.PRESETS)
    items = [
        (str(index), presets.PRESETS[name].label, presets.PRESETS[name].description)
        for index, name in enumerate(names, start=1)
    ]
    selected = menu(
        [*items, ("0", "Отмена", "")],
        "ПРОФИЛЬ ТРАНСПОРТА XHTTP",
    )
    if selected == "0" or not selected.isdigit():
        return None
    index = int(selected) - 1
    if not 0 <= index < len(names):
        return None
    return app.plugin_command(
        state,
        "vless",
        "set_preset",
        preset=names[index],
    )


__all__ = ["open_menu", "option"]
