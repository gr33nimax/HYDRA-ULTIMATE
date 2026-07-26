"""TUI adapter for VLESS/XHTTP desired settings."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.tui import error, menu, prompt, success


def option(_desired: PluginState) -> tuple[str, str]:
    return "⚙️  Настройки", "Домен, путь и режим XHTTP"


def open_menu(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    while True:
        state = app.admin.load_state()
        desired = state.protocols.get("vless") or PluginState()
        domain = str(desired.config.get("domain", ""))
        path = str(desired.config.get("xhttp_path", "/xhttp"))
        mode = str(desired.config.get("xhttp_mode", "stream-up"))
        choice = menu(
            [
                ("1", "Домен", domain or "не настроен"),
                ("2", "XHTTP path", path),
                ("3", "XHTTP mode", mode),
                ("0", "← Назад", ""),
            ],
            "НАСТРОЙКИ VLESS + XHTTP",
        )
        if choice == "0":
            return
        try:
            changed = _change(choice, state, desired, app)
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
    return None


__all__ = ["open_menu", "option"]
