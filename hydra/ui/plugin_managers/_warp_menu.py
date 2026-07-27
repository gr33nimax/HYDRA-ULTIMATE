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


def _wgcf_failure_message(
    app: ApplicationService,
    summary: str,
) -> str:
    """Return a bounded, operator-visible WGCF failure without exposing files."""
    try:
        result = app.logs.read(
            "file",
            "/var/log/hydra/warp_install.log",
            8,
        )
    except Exception:
        return summary
    details = [
        str(line).strip()
        for line in result.lines
        if str(line).strip()
    ]
    if not details:
        return summary
    return f"{summary}\n  Детали: {' | '.join(details[-8:])}"


def _runtime(app: ApplicationService):
    status = app.protocols.status("warp")
    observation = facade._warp_observation(app)
    profile_rows = observation.get("profiles", [])
    profiles = sorted(
        str(row["name"])
        for row in profile_rows
        if isinstance(row, dict) and row.get("name")
    )
    default_exists = bool(
        observation.get("default_profile_exists"),
    )
    destinations = [
        "direct",
        *(f"warp_{profile}" for profile in profiles),
    ]
    if default_exists:
        destinations.append("warp")
    return (
        status,
        profiles,
        default_exists,
        destinations,
        facade._external_sources(app),
    )


def _route_name(
    key: str,
    external_sources: dict[str, dict[str, str]],
) -> str:
    if key.startswith("ext:"):
        source = key.split(":", 1)[1]
        return (
            external_sources.get(source, {}).get("name", source)
            + " (внешн.)"
        )
    return key.split(":", 1)[1] + " (локал.)"


def _status_lines(
    status,
    profiles: list[str],
    destinations: list[str],
    list_targets: dict,
    external_sources: dict[str, dict[str, str]],
) -> list[str]:
    if not status.installed and not profiles:
        return [
            f"  Статус:      {RED}не установлен{NC} "
            "(нет WGCF профиля и гео-релеев)",
        ]
    lines = [
        f"  Статус:      "
        f"{(GREEN + '● активен') if status.running else (DIM + '○ остановлен (выключен)')}{NC}",
        f"  Включён:     {GREEN if status.enabled else DIM}"
        f"{'да' if status.enabled else 'нет'}{NC}",
        "  " + "─" * 45,
        f"  {BOLD}Точки выхода (Egress):{NC}",
        f"  • direct:         {GREEN}работает{NC}",
        (
            f"  • warp (дефолт):  {GREEN}активен{NC}"
            if "warp" in destinations
            else f"  • warp (дефолт):  {DIM}не настроен{NC}"
        ),
    ]
    lines.extend(
        f"  • warp_{profile}:       {CYAN}"
        f"{'активен (релей)' if status.enabled else 'настроен (не активен)'}{NC}"
        for profile in profiles
    )
    lines.extend([
        "  " + "─" * 45,
        f"  {BOLD}Маршруты списков правил:{NC}",
    ])
    if not status.enabled:
        lines.append(
            f"  {YELLOW}WARP выключен: маршруты WARP сейчас не применяются.{NC}",
        )
    active = [
        (key, target)
        for key, target in list_targets.items()
        if target and target != "none"
    ]
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
            f"  • {_route_name(key, external_sources):<22} → "
            f"{color}{rendered_target}{NC}",
        )
    if not active:
        lines.append(
            f"  {YELLOW}Нет активных маршрутов. Настройте их ниже.{NC}",
        )
    return lines


def _options(
    status,
    profiles: list[str],
    default_exists: bool,
) -> list[tuple[str, str, str]]:
    if not status.installed and not profiles:
        options = [
            (
                "1",
                "🔧 Установить Cloudflare WARP (WGCF)",
                "Скачать и настроить локальный профиль по умолчанию",
            ),
            (
                "4",
                "⚙️ Управление профилями релеев",
                "Добавить сторонние профили AmneziaWG/WireGuard",
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
                "⚙️ Управление профилями релеев",
                "Добавить/удалить кастомные профили релеев",
            ),
            (
                "5",
                "🔄 Обновить внешние списки сейчас",
                "Загрузить свежие списки правил с GitHub",
            ),
            ("-", "", ""),
        ]
        if default_exists:
            options.extend([
                (
                    "8",
                    "🔄 Пересоздать локальный WGCF",
                    "Перегенерировать стандартный профиль WARP",
                ),
                (
                    "9",
                    "❌ Удалить локальный WGCF",
                    "Удалить стандартный профиль WARP",
                ),
            ])
        else:
            options.append(
                (
                    "8",
                    "🔧 Установить локальный WGCF",
                    "Скачать и сгенерировать стандартный профиль WARP",
                ),
            )
    options.append(("0", "↩ Назад", ""))
    return options


def _toggle_or_install(
    state: AppState,
    app: ApplicationService,
    status,
    profiles: list[str],
) -> None:
    if not status.installed and not profiles:
        info("Устанавливаю и регистрирую Cloudflare WARP...")
        if app.protocols.install(state, "warp"):
            success("WARP успешно установлен!")
        else:
            error("Не удалось выполнить установку.")
        prompt("Нажмите Enter для продолжения")
        return
    info("Выключаю WARP..." if status.enabled else "Включаю WARP...")
    changed = (
        app.protocols.disable(state, "warp")
        if status.enabled
        else app.protocols.enable(state, "warp")
    )
    if changed:
        success(
            "WARP успешно выключен."
            if status.enabled
            else "WARP успешно включен.",
        )
    else:
        error(
            "Ошибка при выключении WARP."
            if status.enabled
            else "Ошибка при включении WARP.",
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


def _recreate_or_install_profile(
    state: AppState,
    app: ApplicationService,
    plugin_state: PluginState,
    default_exists: bool,
) -> None:
    if not default_exists:
        info("Устанавливаю локальный WGCF...")
        result = app.protocols.lifecycle_result(
            state,
            "install",
            "warp",
        )
        if result:
            success("Локальный WGCF профиль успешно создан!")
            if plugin_state.enabled:
                if not app.apply(state):
                    detail = app.apply_error() or "неизвестная ошибка применения"
                    error(
                        f"WGCF создан, но конфигурация не применена: {detail}",
                    )
        else:
            detail = (
                result.error.message
                if result.error is not None
                else "неизвестная ошибка установки"
            )
            error(
                _wgcf_failure_message(
                    app,
                    f"Не удалось установить локальный WGCF: {detail}",
                ),
            )
        prompt("Нажмите Enter для продолжения")
        return
    warn("ПЕРЕУСТАНОВКА WGCF!")
    if confirm("Продолжить?", default=False):
        previous = app.plugin_action("warp", "snapshot_local_profile")
        if app.plugin_action("warp", "recreate_local_profile"):
            if plugin_state.enabled and not app.apply(state):
                detail = app.apply_error() or "неизвестная ошибка применения"
                app.plugin_action(
                    "warp",
                    "restore_local_profile",
                    snapshot=previous,
                )
                state.protocols["warp"] = plugin_state
                error(f"Новый профиль отклонён и заменён прежним: {detail}")
                facade._show_diagnostic_info(app)
            else:
                success(
                    "Локальный WGCF профиль успешно "
                    "пересоздан и применён!",
                )
        else:
            error(
                _wgcf_failure_message(
                    app,
                    "Не удалось пересоздать локальный WGCF профиль.",
                ),
            )
    prompt("Нажмите Enter для продолжения")


def _remove_profile(
    state: AppState,
    app: ApplicationService,
    plugin_state: PluginState,
    profiles: list[str],
) -> None:
    warn("УДАЛЕНИЕ ЛОКАЛЬНОГО WGCF!")
    if confirm("Вы уверены?", default=False):
        if profiles:
            app.plugin_action("warp", "remove_local_profile")
            if plugin_state.enabled and not app.apply(state):
                error("Профиль удалён, но не удалось применить конфигурацию.")
            else:
                success("Локальный WGCF профиль успешно удален.")
        elif app.protocols.uninstall(state, "warp"):
            success("Локальный WGCF профиль успешно удален.")
        else:
            error("Не удалось удалить локальный WGCF профиль.")
    prompt("Нажмите Enter для продолжения")


def _dispatch(
    choice: str,
    state: AppState,
    app: ApplicationService,
    plugin_state: PluginState,
    status,
    profiles: list[str],
    default_exists: bool,
    destinations: list[str],
) -> None:
    available = status.installed or profiles
    if choice == "1":
        _toggle_or_install(state, app, status, profiles)
    elif choice == "2" and available:
        facade._menu_rules_lists(state, plugin_state, app)
    elif choice == "3" and available:
        facade._menu_routing_rules(
            state,
            plugin_state,
            destinations,
            app,
        )
    elif choice == "4":
        facade._menu_geo_profiles(state, plugin_state, app)
    elif choice == "5" and available:
        _update_external_rules(state, app, plugin_state)
    elif choice == "8":
        _recreate_or_install_profile(
            state,
            app,
            plugin_state,
            default_exists,
        )
    elif choice == "9" and default_exists:
        _remove_profile(state, app, plugin_state, profiles)


def run(state: AppState, app: ApplicationService) -> None:
    plugin_state = state.protocols.setdefault("warp", PluginState())
    if not plugin_state.config:
        plugin_state.config = {}
    while True:
        clear()
        (
            status,
            profiles,
            default_exists,
            destinations,
            external_sources,
        ) = _runtime(app)
        plugin_state.config.setdefault("local_lists", {})
        list_targets = plugin_state.config.setdefault("list_targets", {})
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
            _options(status, profiles, default_exists),
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
            profiles,
            default_exists,
            destinations,
        )


__all__ = ["run"]
