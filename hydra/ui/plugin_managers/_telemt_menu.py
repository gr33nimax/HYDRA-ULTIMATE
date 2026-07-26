"""Main TeleMT manager menu assembled through the stable facade."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _ensure_protocol_state(state: facade.AppState) -> facade.PluginState:
    protocol = state.protocols.setdefault("telemt", facade.PluginState())
    if not protocol.config:
        protocol.config = {
            "port": facade.DEFAULT_PORT,
            "tls_domain": state.network.domain or "google.com",
            "ipv4": True,
            "ipv6": False,
            "client_mss": "",
            "use_middle_proxy": False,
            "fallback_cfg": None,
            "singbox_integration_enabled": False,
            "singbox_integration_port": 10811,
            "syn_limiter_enabled": False,
            "ios_fix_enabled": False,
        }
    return protocol


def _singbox_status(
    protocol: facade.PluginState,
    *,
    installed: bool,
) -> str:
    enabled = protocol.config.get("singbox_integration_enabled", False)
    if not enabled:
        return f"{facade.DIM}выключена (direct){facade.NC}"

    port = protocol.config.get("singbox_integration_port", 10811)
    self_route = facade._get_self_route_module()
    route = (
        self_route.status()
        if self_route and installed
        else {"return_rule": False, "after_xray": False}
    )
    suffix = (
        f"{facade.GREEN}[rule: OK]{facade.NC}"
        if route.get("return_rule") and route.get("after_xray")
        else f"{facade.YELLOW}[rule: нет]{facade.NC}"
    )
    return (
        f"{facade.GREEN}активна (redirect :{port}){facade.NC}"
        f"  {suffix}"
    )


def _status_details(
    protocol: facade.PluginState,
    app: facade.ApplicationService,
    *,
    installed: bool,
    version: str | None,
) -> list[tuple[str, object]]:
    details: list[tuple[str, object]] = [
        ("Версия", version),
        ("Домен TLS", protocol.config.get("tls_domain", "—")),
        ("Sing-Box", _singbox_status(protocol, installed=installed)),
        ("Подсети TG", facade.tg_nets_status_line()),
    ]
    config_exists = app.diagnostics.path_exists(str(facade.CONFIG_FILE))
    if not config_exists:
        return details

    fallback = facade._get_fallback_module()
    if fallback:
        details.append(
            ("Fallback", fallback.fallback_status_line(facade.CONFIG_FILE)),
        )
    syn_limiter = facade._get_syn_limiter_module()
    if syn_limiter:
        details.append(("SYN-limiter", syn_limiter.syn_limiter_status_line()))
    ios_fix = facade._get_ios_fix_module()
    if ios_fix:
        details.append(("iOS-фикс", ios_fix.ios_fix_status_line()))
    return details


def _render_status(
    protocol: facade.PluginState,
    app: facade.ApplicationService,
) -> tuple[bool, bool]:
    plugin_status = app.protocols.status("telemt")
    installed = plugin_status.installed
    running = plugin_status.running
    version = facade._get_installed_version(app) if installed else None
    facade.protocol_status_panel(
        "telemt",
        installed=installed,
        enabled=protocol.enabled,
        running=running,
        port=protocol.config.get("port", facade.DEFAULT_PORT),
        details=_status_details(
            protocol,
            app,
            installed=installed,
            version=version,
        ),
    )
    return installed, running


def _menu_options(enabled: bool) -> list[tuple[str, str, str]]:
    return [
        (
            "1",
            "🚀  Установить / Переустановить",
            "Интерактивная настройка с нуля",
        ),
        (
            "2",
            "👥  Просмотр пользователей и ссылок",
            "Показать учетные записи и ссылки для подключения",
        ),
        ("3", "🔄  Перезапустить сервис", "Сброс службы telemt"),
        (
            "4",
            "⬆️   Проверить и обновить бинарник",
            "Обновление telemt до последней версии с GitHub",
        ),
        (
            "5",
            "📊  Статистика трафика",
            "Просмотр статистики по сессиям и байтам",
        ),
        (
            "6",
            "📋  Статус службы / журналы логов",
            "Журналы systemd и stdout",
        ),
        (
            "7",
            "⏸️   Отключить TeleMT" if enabled else "▶️   Включить TeleMT",
            "Изменить конфигурацию и состояние службы согласованно",
        ),
        (
            "X",
            "🌐  Sing-Box-интеграция (обход блоков)",
            "Заворот Telegram трафика в Sing-Box/WARP",
        ),
        (
            "F",
            "🔀  Hybrid Fallback (Middle ↔ Direct)",
            "Параметры резервирования связи",
        ),
        (
            "S",
            "🛡️   SYN-limiter (защита от флуда)",
            "Ограничение скорости SYN-пакетов",
        ),
        (
            "I",
            "🍎  iOS-фикс (MSS + порт)",
            "Обход блокировок на Apple устройствах",
        ),
        (
            "N",
            "🌐  Обновить подсети Telegram (RIPE)",
            "Загрузить свежие диапазоны IP Telegram",
        ),
        (
            "9",
            f"{facade.RED}🗑️   Полное удаление{facade.NC}",
            "Удалить сервис, правила фаервола и бинарник",
        ),
        ("-", "", ""),
        ("0", "↩ Назад в главное меню", ""),
    ]


def _restart(app: facade.ApplicationService) -> None:
    facade.info("Перезапускаю telemt...")
    app.admin.restart_unit(facade.SERVICE_NAME)
    facade.success("Служба перезапущена.")
    facade._pause()


def _show_stats(state: facade.AppState) -> None:
    stats = facade._get_stats_module()
    if stats:
        stats.stats_menu(state=state)
        return
    facade.error("Модуль статистики mtproto_stats недоступен.")
    facade._pause()


def _toggle(
    state: facade.AppState,
    app: facade.ApplicationService,
    protocol: facade.PluginState,
    *,
    installed: bool,
) -> None:
    target_enabled = not protocol.enabled
    if target_enabled and not installed:
        facade.warn("Сначала установите TeleMT.")
    elif not target_enabled and not facade.confirm("Отключить TeleMT?"):
        return
    else:
        facade.info(
            "Включаю TeleMT..."
            if target_enabled
            else "Отключаю TeleMT...",
        )
        if facade._set_telemt_enabled(state, target_enabled, app):
            facade.success(
                "TeleMT включён."
                if target_enabled
                else "TeleMT отключён.",
            )
        else:
            detail = app.apply_error()
            facade.error(
                detail
                or "Не удалось изменить состояние TeleMT.",
            )
    facade._pause()


def _uninstall(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    if not facade.confirm(
        "Вы уверены, что хотите полностью удалить Telemt?",
    ):
        return
    facade._run_uninstall(state, app)
    facade._pause()


def _dispatch(
    choice: str,
    state: facade.AppState,
    app: facade.ApplicationService,
    protocol: facade.PluginState,
    *,
    installed: bool,
) -> bool:
    choice = choice.lower()
    if choice == "0":
        return False
    if choice == "1":
        facade._run_install(state, app)
    elif choice == "2":
        facade._view_links(state, app)
    elif choice == "3":
        _restart(app)
    elif choice == "4":
        facade._run_update(app)
    elif choice == "5":
        _show_stats(state)
    elif choice == "6":
        facade._view_logs(app)
    elif choice == "7":
        _toggle(state, app, protocol, installed=installed)
    elif choice == "9":
        _uninstall(state, app)
    elif choice == "x":
        facade._menu_singbox_integration(state, app)
    elif choice == "f":
        facade._menu_fallback(state, app)
    elif choice == "s":
        facade._menu_syn_limiter()
    elif choice == "i":
        facade._menu_ios_fix()
    elif choice == "n":
        facade._menu_update_tg_nets(state, app)
    return True


def run(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    protocol = _ensure_protocol_state(state)
    while True:
        facade.clear()
        installed, _running = _render_status(protocol, app)
        choice = facade.menu(
            _menu_options(protocol.enabled),
            facade.protocol_menu_title("telemt"),
        )
        try:
            if not _dispatch(
                choice,
                state,
                app,
                protocol,
                installed=installed,
            ):
                return
        except facade._Cancelled:
            facade.info("Операция отменена.")
            facade._pause()
        except Exception as exc:
            facade.error(f"Неожиданная ошибка: {exc}")
            facade._pause()
