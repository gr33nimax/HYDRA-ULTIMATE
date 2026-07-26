"""Optional TeleMT feature menus exposed through the stable manager facade."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _apply_state(
    state: facade.AppState,
    app: facade.ApplicationService,
    *,
    success_message: str,
) -> None:
    facade.info("Применяю изменения...")
    if app.apply(state):
        facade.success(success_message)
    else:
        facade.error("Не удалось применить конфигурацию.")


def menu_singbox_integration(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    config = state.protocols["telemt"].config
    enabled = config.get("singbox_integration_enabled", False)
    port = config.get("singbox_integration_port", 10811)
    status = "🟢 АКТИВНА" if enabled else "🔴 ОТКЛЮЧЕНА (direct)"
    facade.panel(
        "🌐 ИНТЕГРАЦИЯ С SING-BOX / WARP",
        [
            f"  Текущий статус: {status}",
            f"  Порт перехвата: {port}",
            "",
            "  При включении трафик Telemt к подсетям Telegram",
            "  перенаправляется в Sing-Box и уходит через WARP.",
        ],
    )
    choice = facade.menu(
        [
            (
                "1",
                (
                    "⏸️  Отключить"
                    if enabled
                    else "▶️  Включить"
                )
                + " интеграцию с Sing-Box",
                "",
            ),
            (
                "2",
                "⚙️  Изменить порт перехвата Sing-Box",
                "",
            ),
            ("0", "↩ Назад", ""),
        ],
        "НАСТРОЙКА SING-BOX CASCADE",
    )
    if choice == "1":
        config["singbox_integration_enabled"] = not enabled
        app.admin.save_state(state)
        _apply_state(
            state,
            app,
            success_message="Конфигурация обновлена!",
        )
        facade._pause()
    elif choice == "2":
        _change_singbox_port(state, app)


def _change_singbox_port(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    try:
        port = int(
            facade._ask(
                "Введите порт перехвата redirect (например, 10811)",
            ),
        )
    except (ValueError, facade._Cancelled):
        return
    if not 1024 <= port <= 65535:
        facade.error("Неверный порт.")
        facade._pause()
        return
    state.protocols["telemt"].config["singbox_integration_port"] = port
    app.admin.save_state(state)
    _apply_state(
        state,
        app,
        success_message="Порт перехвата обновлен!",
    )
    facade._pause()


def _fallback_status_lines(
    state: facade.AppState,
    app: facade.ApplicationService,
    fallback,
) -> list[str]:
    config = state.protocols["telemt"].config
    use_middle_proxy = config.get("use_middle_proxy", False)
    fallback_config = config.get("fallback_cfg")
    runtime_middle_proxy = (
        fallback.read_runtime_middle_proxy(facade.CONFIG_FILE)
        if app.diagnostics.path_exists(str(facade.CONFIG_FILE))
        else False
    )
    lines = [
        "  Использовать Middle Proxy: "
        + ("да" if use_middle_proxy else "нет"),
        "  Текущий рантайм-режим:    "
        + ("Middle Proxy" if runtime_middle_proxy else "Direct Mode"),
    ]
    if not fallback_config:
        lines.append("  Авто-fallback:             не настроен")
        return lines
    lines.extend(
        [
            "  Авто-fallback к Direct:    "
            f"{fallback_config.get('fallback_to_direct')}",
            "  Попыток до fallback:       "
            f"{fallback_config.get('fallback_after_attempts')}",
            "  Таймаут проверки (сек):     "
            f"{fallback_config.get('fallback_after_seconds')}",
        ],
    )
    return lines


def _configure_fallback(
    state: facade.AppState,
    app: facade.ApplicationService,
    fallback,
) -> None:
    use_middle_proxy = facade.confirm(
        "Использовать Middle Proxy по умолчанию?",
    )
    config = state.protocols["telemt"].config
    config["use_middle_proxy"] = use_middle_proxy
    if not use_middle_proxy:
        config["fallback_cfg"] = None
    elif facade.confirm(
        "Настроить автоматический fallback на Direct?",
    ):
        selected = fallback.me_probe_menu(facade.CONFIG_FILE)
        config["fallback_cfg"] = facade.asdict(selected)
    else:
        config["fallback_cfg"] = facade.asdict(
            fallback.FallbackConfig.defaults(),
        )
    app.admin.save_state(state)
    facade.info("Перезаписываю конфигурацию...")
    if app.apply(state):
        facade.success("Настройки успешно изменены!")
    else:
        facade.error("Ошибка применения конфигурации.")
    facade._pause()


def _probe_fallback(fallback) -> None:
    print()
    facade.info("Проверяю доступность ME-серверов Telegram...")
    live = fallback.fetch_live_me_endpoints()
    source = (
        f"живой пул getProxyConfig ({len(live)} адресов)"
        if live
        else "статический fallback-список"
    )
    facade.info(f"Источник: {source}")
    available, total = fallback.diagnostic_probe().probe_all()
    ratio = available / total if total else 0
    quorum = fallback.middle_proxy_quorum()
    if ratio >= quorum:
        facade.success(
            f"ME-серверы доступны: {available}/{total} ({ratio:.0%})",
        )
    else:
        facade.warn(
            "ME-серверы недоступны: "
            f"{available}/{total} ({ratio:.0%} < кворум {quorum:.0%})",
        )
    facade._pause()


def _switch_fallback_runtime(fallback, *, enable: bool) -> None:
    mode = "Middle Proxy" if enable else "Direct Mode"
    facade.info(f"Переключаю в {mode} (runtime)...")
    if not fallback.set_runtime_middle_proxy(
        facade.CONFIG_FILE,
        enable=enable,
    ):
        facade.error("Не удалось записать конфигурационный файл.")
        facade._pause()
        return
    applied, method = fallback.apply_telemt_reload(facade.SERVICE_NAME)
    if applied:
        facade.success(f"Успешно переключено в {mode} через {method}.")
    else:
        facade.error("Не удалось применить изменения к telemt.")
    facade._pause()


def menu_fallback(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    fallback = facade._get_fallback_module()
    if not fallback:
        facade.error("Модуль fallback недоступен.")
        facade._pause()
        return
    while True:
        facade.clear()
        facade.panel(
            "🔀 HYBRID FALLBACK CONTROL",
            _fallback_status_lines(state, app, fallback),
        )
        choice = facade.menu(
            [
                (
                    "1",
                    "⚙️  Изменить параметры fallback и режим",
                    "",
                ),
                (
                    "2",
                    "🔍  Проверить доступность ME-серверов сейчас",
                    "",
                ),
                (
                    "3",
                    "▶️   Применить Direct Mode вручную (runtime)",
                    "",
                ),
                (
                    "4",
                    "◀️   Применить Middle Proxy вручную (runtime)",
                    "",
                ),
                ("0", "↩ Назад", ""),
            ],
            "FALLBACK МЕНЮ",
        )
        if choice == "0":
            return
        if choice == "1":
            _configure_fallback(state, app, fallback)
        elif choice == "2":
            _probe_fallback(fallback)
        elif choice == "3":
            _switch_fallback_runtime(fallback, enable=False)
        elif choice == "4":
            _switch_fallback_runtime(fallback, enable=True)


def menu_syn_limiter() -> None:
    syn_limiter = facade._get_syn_limiter_module()
    if not syn_limiter:
        facade.error("Модуль SYN-лимитера недоступен.")
        facade._pause()
        return
    try:
        syn_limiter.syn_limiter_menu()
    except facade._Cancelled:
        pass


def menu_ios_fix() -> None:
    ios_fix = facade._get_ios_fix_module()
    if not ios_fix:
        facade.error("Модуль iOS-фикса недоступен.")
        facade._pause()
        return
    try:
        ios_fix.ios_fix_menu()
    except facade._Cancelled:
        pass


def menu_update_tg_nets(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.panel(
        "🌐 ОБНОВЛЕНИЕ ПОДСЕТЕЙ TELEGRAM",
        [
            "  Источники: RIPE NCC (BGP announced-prefixes)",
            "  ASN: AS62041, AS59930, AS44907, AS211157, AS42065",
            "",
            "  Новые диапазоны будут применены",
            "  в правилах перехвата трафика Sing-Box/iptables.",
        ],
    )
    if not facade.confirm("Обновить подсети Telegram сейчас?"):
        return
    facade.update_tg_nets_interactive()
    enabled = state.protocols["telemt"].config.get(
        "singbox_integration_enabled",
        False,
    )
    if enabled:
        _apply_updated_tg_nets(state, app)
    else:
        facade.success(
            "Список обновлен на диске (/etc/telemt/tg_nets.txt).",
        )
        facade.info(
            "Интеграция Sing-Box выключена, "
            "перезапись фаервола не требуется.",
        )
    facade._pause()


def _apply_updated_tg_nets(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.info("Перенастраиваю iptables-перехват...")
    self_route = facade._get_self_route_module()
    if not self_route:
        facade.error("Модуль self-route недоступен.")
        return
    self_route.disable()
    if app.apply(state):
        facade.success(
            "Диапазоны обновлены и применены к фаерволу!",
        )
    else:
        facade.error("Не удалось применить конфигурацию.")
