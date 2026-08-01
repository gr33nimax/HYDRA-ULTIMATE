"""Install, update, log and uninstall operations for the TeleMT UI."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _choose_network() -> tuple[bool, bool]:
    choice = facade.menu(
        [
            ("1", "Только IPv4", ""),
            ("2", "Только IPv6", ""),
            ("3", "DualStack IPv4+IPv6 (Рекомендуется)", ""),
        ],
        "ВЫБЕРИТЕ СЕТЕВОЙ ПРОТОКОЛ",
    )
    return choice in ("1", "3"), choice in ("2", "3")


def _choose_port() -> int | None:
    choice = facade.menu(
        [
            ("1", "Стандартный 8443 (Рекомендуется)", ""),
            ("2", "443 (под вид веб-трафика)", ""),
            ("3", "Ввести свой порт вручную", ""),
        ],
        "ВЫБЕРИТЕ ПОРТ ПРОКСИ",
    )
    if choice == "1":
        return 8443
    if choice == "2":
        return 443
    while True:
        try:
            port = int(facade._ask("Введите порт (1024-65535)"))
        except (ValueError, facade._Cancelled):
            return None
        if 1024 <= port <= 65535:
            return port
        facade.error("Неверный диапазон порта.")


def _choose_client_mss() -> str:
    selector = facade._get_mss_module()
    if not selector:
        return ""
    return selector.mss_select_interactive()


def _choose_middle_proxy() -> tuple[bool, object | None]:
    choice = facade.menu(
        [
            (
                "1",
                "Да, Telegram заблокирован (РФ / NAT) -> Direct Mode",
                "",
            ),
            (
                "2",
                "Нет, Telegram доступен напрямую -> Middle Proxy",
                "",
            ),
        ],
        "ЗАБЛОКИРОВАН ЛИ TELEGRAM НА ЭТОМ СЕРВЕРЕ?",
    )
    use_middle_proxy = choice == "2"
    if not use_middle_proxy:
        return False, None

    fallback = facade._get_fallback_module()
    if not fallback:
        return True, None
    if facade.confirm(
        "Настроить автоматический fallback на Direct Mode "
        "при сбое Middle Proxy?",
    ):
        return True, fallback.me_probe_menu(facade.CONFIG_FILE)
    return True, fallback.FallbackConfig.defaults()


def _save_install_settings(
    state: facade.AppState,
    app: facade.ApplicationService,
    *,
    port: int,
    tls_domain: str,
    ipv4: bool,
    ipv6: bool,
    client_mss: str,
    use_middle_proxy: bool,
    fallback_config: object | None,
    singbox_integration: bool,
) -> None:
    config = state.protocols["telemt"].config
    config.update(
        {
            "port": port,
            "tls_domain": tls_domain,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "client_mss": client_mss,
            "use_middle_proxy": use_middle_proxy,
            "fallback_cfg": (
                facade.asdict(fallback_config)
                if fallback_config
                else None
            ),
            "singbox_integration_enabled": singbox_integration,
        },
    )
    app.admin.save_state(state)


def _install_or_repair(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> bool:
    """Install TeleMT once, or repair an already installed service."""
    protocol = state.protocols.get("telemt")
    if protocol is None:
        return app.protocols.install(state, "telemt")

    was_installed = protocol.installed
    # Avoid applying the pending configuration twice.  The explicit enable
    # immediately after this operation owns the centralized apply.
    protocol.enabled = False
    app.admin.save_state(state)
    if was_installed:
        return app.protocols.reinstall(state, "telemt")
    return app.protocols.install(state, "telemt")


def run_install(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.warn("Начинаю установку / настройку Telemt MTProxy...")
    ipv4, ipv6 = _choose_network()
    port = _choose_port()
    if port is None:
        return
    tls_domain = facade._ask(
        "Введите домен маскировки TLS (например, google.com)",
        default=state.network.domain or "google.com",
    )
    try:
        client_mss = _choose_client_mss()
    except facade._Cancelled:
        return
    use_middle_proxy, fallback_config = _choose_middle_proxy()
    singbox_integration = facade.confirm(
        "Направить исходящий трафик Telemt через Sing-Box "
        "(нужно для WARP в РФ)?",
    )
    _save_install_settings(
        state,
        app,
        port=port,
        tls_domain=tls_domain,
        ipv4=ipv4,
        ipv6=ipv6,
        client_mss=client_mss,
        use_middle_proxy=use_middle_proxy,
        fallback_config=fallback_config,
        singbox_integration=singbox_integration,
    )

    facade.info("Скачиваю зависимости и бинарник telemt...")
    if not (
        _install_or_repair(state, app)
        and app.protocols.enable(state, "telemt")
    ):
        facade.error("Установка бинарника провалилась.")
        facade._pause()
        return
    facade.success("Установка успешно завершена!")
    apply_optimizations(app)
    facade._pause()


def view_links(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    if not state.users:
        facade.warn(
            "Нет активных пользователей в системе. "
            "Создайте пользователя в меню 'Пользователи'.",
        )
        facade._pause()
        return

    lines: list[str] = []
    for user in state.users:
        if user.blocked:
            continue
        links = app.protocols.client_links(state, "telemt", user)
        lines.append(f"{facade.BOLD}{user.email}{facade.NC}")
        for index, link in enumerate(links):
            prefix = f"{facade.DIM}└─ iOS:{facade.NC}" if index else ""
            lines.append(f"  {prefix} {facade.YELLOW}{link}{facade.NC}")
        lines.append("")
    facade.panel("🔗 ССЫЛКИ ДЛЯ ПОДКЛЮЧЕНИЯ TELEGRAM", lines, wrap=True)
    facade._pause()


def run_update(app: facade.ApplicationService) -> None:
    from hydra.plugins.telemt.plugin import GITHUB_REPO
    from hydra.utils.downloader import latest_release

    facade.clear()
    facade.info("Проверяю обновления Telemt...")
    current = facade._get_installed_version(app) or "unknown"
    latest = latest_release(GITHUB_REPO)
    print(f"  Установленная версия: {current}")
    print(f"  Последняя на GitHub:  {latest}")
    print()
    if current == latest:
        facade.success("У вас уже установлена последняя версия!")
        facade._pause()
        return
    if facade.confirm(f"Обновить Telemt до версии {latest}?"):
        facade.info("Скачиваю обновление...")
        if app.plugin_action("telemt", "update_binary"):
            app.admin.restart_unit(facade.SERVICE_NAME)
            facade.success("Telemt успешно обновлён!")
        else:
            facade.error("Обновление завершилось с ошибкой.")
        facade._pause()


def view_logs(app: facade.ApplicationService) -> None:
    facade.clear()
    facade.panel("СТАТУС СЛУЖБЫ TELEMT", [])
    status = app.admin.run_command(
        ["systemctl", "status", facade.SERVICE_NAME, "--no-pager"],
        capture_output=True,
        text=True,
    )
    print(status.stdout or status.stderr)
    print(
        f"\n{facade.BOLD}{facade.CYAN}"
        f"Последние 25 строк логов:{facade.NC}",
    )
    journal = app.admin.run_command(
        [
            "journalctl",
            "-u",
            facade.SERVICE_NAME,
            "-n",
            "25",
            "--no-pager",
        ],
        capture_output=True,
        text=True,
    )
    print(journal.stdout or journal.stderr)
    facade._pause()


def run_uninstall(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.info("Удаляю службу Telemt MTProxy...")
    self_route = facade._get_self_route_module()
    if self_route:
        self_route.disable()
    ios_fix = facade._get_ios_fix_module()
    if ios_fix:
        ios_fix.disable_ios_fix()
    syn_limiter = facade._get_syn_limiter_module()
    if syn_limiter:
        syn_limiter.disable_syn_limiter()
    stats = facade._get_stats_module()
    if stats:
        stats.reset_accounting()
    app.plugin_action("telemt", "remove_optimizations")
    if app.protocols.uninstall(state, "telemt"):
        facade.success("Telemt полностью удален с сервера.")
    else:
        facade.error("Ошибка при удалении файлов плагина.")


def apply_optimizations(app: facade.ApplicationService) -> None:
    """Apply the optional TeleMT host tuning action without blocking install."""
    try:
        app.plugin_action("telemt", "apply_optimizations")
    except Exception:
        pass
