"""Controller loop and main views for the WARP manager facade."""

from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
    warn,
)


def _runtime(app: ApplicationService):
    status = app.protocols.status("warp")
    observation = facade._warp_observation(app)
    profile_rows = observation.get("profiles", [])
    profiles = sorted(str(row["name"]) for row in profile_rows if isinstance(row, dict) and row.get("name"))
    destinations = [
        "direct",
        "warp",
        *(f"warp_{profile}" for profile in profiles),
    ]
    return (
        status,
        profiles,
        destinations,
        facade._external_sources(app),
    )


def _route_name(
    key: str,
    external_sources: dict[str, dict[str, str]],
) -> str:
    if key.startswith("ext:"):
        source = key.split(":", 1)[1]
        return external_sources.get(source, {}).get("name", source) + " (внешн.)"
    return key.split(":", 1)[1] + " (локал.)"


def _status_lines(
    status,
    profiles: list[str],
    destinations: list[str],
    list_targets: dict,
    external_sources: dict[str, dict[str, str]],
) -> list[str]:
    lines = [
        f"  Статус:      {(GREEN + '● активен') if status.running else (DIM + '○ остановлен (выключен)')}{NC}",
        f"  Включён:     {GREEN if status.enabled else DIM}{'да' if status.enabled else 'нет'}{NC}",
        "  " + "─" * 45,
        f"  {BOLD}Точки выхода (Egress):{NC}",
        f"  • direct:         {GREEN}работает{NC}",
        f"  • warp (MASQUE):  {GREEN if status.enabled else DIM}{'включён' if status.enabled else 'выключен'}{NC}",
    ]
    lines.extend(
        f"  • warp_{profile}:       {CYAN}{'активен (релей)' if status.enabled else 'настроен (не активен)'}{NC}"
        for profile in profiles
    )
    lines.extend(
        [
            "  " + "─" * 45,
            f"  {BOLD}Маршруты списков правил:{NC}",
        ]
    )
    if not status.enabled:
        lines.append(
            f"  {YELLOW}WARP выключен: маршруты WARP сейчас не применяются.{NC}",
        )
    active = [(key, target) for key, target in list_targets.items() if target and target != "none"]
    for key, target in active:
        if target not in destinations:
            rendered_target = f"{target} (недоступен)"
            color = RED
        elif not status.enabled:
            rendered_target = f"{target} (не применяется)"
            color = DIM
        else:
            rendered_target = target
            color = GREEN if target != "direct" else YELLOW
        lines.append(
            f"  • {_route_name(key, external_sources):<22} → {color}{rendered_target}{NC}",
        )
    if not active:
        lines.append(
            f"  {YELLOW}Нет активных маршрутов. Настройте их ниже.{NC}",
        )
    return lines


def _options(
    status,
) -> list[tuple[str, str, str]]:
    if not status.installed:
        options = [
            (
                "1",
                "🔧 Установить WARP",
                "Подготовить транспорт и заранее загрузить списки правил",
            ),
        ]
    else:
        options = [
            (
                "1",
                f"{'⏸️  Выключить' if status.enabled else '▶️  Включить'} WARP",
                "Переключить статус службы в Sing-Box",
            ),
            (
                "2",
                "📋 Управление списками правил",
                "Добавление/редактирование локальных и внешних списков",
            ),
            (
                "3",
                "🔀 Настройка маршрутизации",
                "Связать списки правил с точками выхода (WARP/релеи)",
            ),
            (
                "4",
                "🌐 Сервер подключения WARP",
                "Найти адрес или вернуть автоматический выбор",
            ),
            (
                "5",
                "⚙️ Управление профилями релеев",
                "Добавить/удалить кастомные профили релеев",
            ),
            (
                "6",
                "🔄 Обновить внешние списки сейчас",
                "Загрузить свежие списки правил с GitHub",
            ),
            ("-", "", ""),
            (
                "8",
                "🔄 Переустановить",
                "Переустановка с сохранением маршрутов",
            ),
            (
                "9",
                "❌ Удалить",
                "Снять маршруты, кэш правил и остатки прежнего установщика",
            ),
        ]
    options.append(("0", "↩ Назад", ""))
    return options


def _install(state: AppState, app: ApplicationService) -> None:
    info("Устанавливаю WARP...")
    if app.protocols.install(state, "warp"):
        success("WARP установлен и готов к работе.")
    else:
        error("Ошибка при установке.")
    prompt("Нажмите Enter для продолжения")


def _reinstall(state: AppState, app: ApplicationService) -> None:
    warn("ПЕРЕУСТАНОВКА WARP!")
    if confirm("Продолжить?", default=False):
        info("Восстанавливаю установку с сохранением маршрутов...")
        if app.protocols.reinstall(state, "warp"):
            success("Успешно переустановлено!")
        else:
            error("Ошибка при переустановке.")
    prompt("Нажмите Enter для продолжения")


def _uninstall(state: AppState, app: ApplicationService) -> None:
    warn("ПОЛНОЕ УДАЛЕНИЕ WARP!")
    if confirm("Вы уверены?", default=False):
        info("Удаляю...")
        if not app.protocols.disable(state, "warp"):
            error("Не удалось отключить WARP перед удалением.")
        elif app.protocols.uninstall(state, "warp"):
            success("WARP полностью удалён.")
        else:
            error("Ошибка при удалении.")
    prompt("Нажмите Enter для продолжения")


def _toggle(
    state: AppState,
    app: ApplicationService,
    status,
) -> None:
    info("Выключаю WARP..." if status.enabled else "Включаю WARP...")
    changed = app.protocols.disable(state, "warp") if status.enabled else app.protocols.enable(state, "warp")
    if changed:
        success(
            "WARP успешно выключен." if status.enabled else "WARP успешно включен.",
        )
    else:
        error(
            "Ошибка при выключении WARP." if status.enabled else "Ошибка при включении WARP.",
        )
        facade._show_diagnostic_info(app)
    prompt("Нажмите Enter для продолжения")


def _update_external_rules(
    state: AppState,
    app: ApplicationService,
    plugin_state: PluginState,
) -> None:
    info("Обновляю внешние списки правил...")
    ok, message = app.plugin_action(
        "warp",
        "update_external_rules",
        state=state,
    )
    if ok:
        success(message)
        if plugin_state.enabled:
            info("Применяю новые правила в Sing-Box...")
            if not app.apply(state):
                error("Ошибка применения нового конфига.")
                facade._show_diagnostic_info(app)
    else:
        error(message)
    prompt("Нажмите Enter для продолжения")


def _dispatch(
    choice: str,
    state: AppState,
    app: ApplicationService,
    plugin_state: PluginState,
    status,
    destinations: list[str],
) -> None:
    if choice == "1":
        if status.installed:
            _toggle(state, app, status)
        else:
            _install(state, app)
    elif choice == "2" and status.installed:
        facade._menu_rules_lists(state, plugin_state, app)
    elif choice == "3" and status.installed:
        facade._menu_routing_rules(
            state,
            plugin_state,
            destinations,
            app,
        )
    elif choice == "4" and status.installed:
        facade._menu_masque(state, app)
    elif choice == "5" and status.installed:
        facade._menu_geo_profiles(state, plugin_state, app)
    elif choice == "6" and status.installed:
        _update_external_rules(state, app, plugin_state)
    elif choice == "8" and status.installed:
        _reinstall(state, app)
    elif choice == "9" and status.installed:
        _uninstall(state, app)


def run(state: AppState, app: ApplicationService) -> None:
    plugin_state = state.protocols.setdefault("warp", PluginState())
    if not plugin_state.config:
        plugin_state.config = {}
    while True:
        clear()
        (
            status,
            profiles,
            destinations,
            external_sources,
        ) = _runtime(app)
        plugin_state.config.setdefault("local_lists", {})
        list_targets = plugin_state.config.get("list_targets")
        if not isinstance(list_targets, dict):
            list_targets = {}
            plugin_state.config["list_targets"] = list_targets
        panel(
            "🌐 УПРАВЛЕНИЕ WARP ROUTING & RELAYS",
            _status_lines(
                status,
                profiles,
                destinations,
                list_targets,
                external_sources,
            ),
        )
        choice = menu(
            _options(status),
            "УПРАВЛЕНИЕ WARP",
        )
        if choice == "0":
            return
        _dispatch(
            choice,
            state,
            app,
            plugin_state,
            status,
            destinations,
        )


__all__ = ["run"]
