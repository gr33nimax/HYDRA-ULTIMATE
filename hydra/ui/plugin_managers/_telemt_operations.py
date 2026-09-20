"""Hydra-facing Telemt install, update, links, logs and uninstall flows."""

from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _choose_port() -> int | None:
    choice = facade.menu(
        [
            ("1", "8443 (рекомендуется)", ""),
            ("2", "443", ""),
            ("3", "Ввести порт", ""),
        ],
        "ПОРТ TELEMT",
    )
    if choice == "1":
        return 8443
    if choice == "2":
        return 443
    try:
        port = int(facade._ask("Порт (1-65535)"))
    except (ValueError, facade._Cancelled):
        return None
    if 1 <= port <= 65535:
        return port
    facade.error("Неверный диапазон порта.")
    return None


def _save_install_settings(state, app, *, port: int, tls_domain: str) -> None:
    config = state.protocols["telemt"].config
    config.update(
        {
            "settings_version": 1,
            "port": port,
            "tls_domain": tls_domain,
            "advanced": {
                "network": "auto",
                "use_middle_proxy": False,
                "log_level": "normal",
            },
        }
    )
    app.admin.save_state(state)


def _install_or_repair(state, app) -> bool:
    protocol = state.protocols.get("telemt")
    if protocol is None:
        return app.protocols.install(state, "telemt")
    protocol.enabled = False
    app.admin.save_state(state)
    return app.protocols.reinstall(state, "telemt") if protocol.installed else app.protocols.install(state, "telemt")


def _port_is_free(app, port: int) -> bool:
    """Preflight probe: another listener may already own this TCP port.

    Uses the wildcard probe so a service bound to one specific address is
    still detected. A missing or failing diagnostic port must never block an
    install; the runtime apply still reports a real bind failure.
    """
    diagnostics = getattr(app, "diagnostics", None)
    probe = getattr(diagnostics, "port_occupied", None) or getattr(diagnostics, "port_listening", None)
    if not callable(probe):
        return True
    try:
        return not bool(probe(port))
    except Exception:
        return True


def _failure_detail(app, fallback: str) -> str:
    """Use the recorded lifecycle failure, or a concrete next step."""
    detail = str(app.apply_error() or "").strip()
    return detail or fallback


def run_install(state, app) -> None:
    from hydra.plugins.telemt.migration import preview

    facade.clear()
    protocol = state.protocols.get("telemt")
    migration = preview(protocol.config) if protocol else None
    if migration and not migration.is_compatible:
        facade.error("Старые Telemt-настройки требуют ручной миграции: " + ", ".join(migration.blockers))
        facade._pause()
        return
    facade.warn("Настройка Telemt Fake TLS.")
    port = _choose_port()
    if port is None:
        return
    current_port = protocol.config.get("port", 0) if protocol else 0
    if port != current_port and not _port_is_free(app, port):
        facade.error(f"Порт {port} уже занят другим сервисом. Выберите свободный порт.")
        facade._pause()
        return
    tls_domain = facade._ask(
        "TLS-домен маскировки (например, google.com)",
        default=state.network.domain or "google.com",
    )
    from hydra.plugins.telemt.configuration import TelemtSettings

    try:
        TelemtSettings(port=port, tls_domain=tls_domain)
    except ValueError as exc:
        facade.error(str(exc))
        facade._pause()
        return
    if (
        protocol
        and protocol.config.get("tls_domain") not in (None, tls_domain)
        and any(not user.blocked for user in state.users)
        and not facade.confirm("Смена TLS-домена сломает старые ссылки. Продолжить?")
    ):
        return
    _save_install_settings(state, app, port=port, tls_domain=tls_domain)
    if not _install_or_repair(state, app):
        facade.error("Установка Telemt не удалась: " + _failure_detail(app, "смотрите journalctl -u telemt"))
        facade._pause()
        return
    if not app.protocols.enable(state, "telemt"):
        facade.error("Telemt установлен, но не запустился: " + _failure_detail(app, "смотрите systemctl status telemt"))
        facade._pause()
        return
    facade.success("Telemt установлен. Выдай пользователям новые ссылки.")
    facade._pause()


def run_advanced(state, app) -> None:
    from hydra.plugins.telemt.configuration import settings_from_state
    from hydra.plugins.telemt.migration import preview

    protocol = state.protocols.get("telemt")
    if protocol is None:
        facade.warn("Сначала настройте Telemt.")
        facade._pause()
        return
    migration = preview(protocol.config)
    if not migration.is_compatible:
        facade.error("Старые Telemt-настройки требуют ручной миграции: " + ", ".join(migration.blockers))
        facade._pause()
        return
    try:
        current = settings_from_state(state)
    except ValueError as exc:
        facade.error(str(exc))
        facade._pause()
        return
    network = facade.menu(
        [
            ("1", "auto", "IPv4 listener по умолчанию"),
            ("2", "ipv4", "Только IPv4"),
            ("3", "ipv6", "Только IPv6"),
            ("4", "dual_stack", "IPv4 и IPv6"),
        ],
        "СЕТЬ TELEMT",
    )
    selected_network = {"1": "auto", "2": "ipv4", "3": "ipv6", "4": "dual_stack"}.get(network)
    if selected_network is None:
        return
    use_middle_proxy = facade.confirm("Включить MiddleProxy?")
    log_choice = facade.menu(
        [("1", "normal", "Обычные логи"), ("2", "debug", "Подробная диагностика")],
        "ЛОГИ TELEMT",
    )
    log_level = {"1": "normal", "2": "debug"}.get(log_choice)
    if log_level is None:
        return
    protocol.config["advanced"] = {
        "network": selected_network,
        "use_middle_proxy": use_middle_proxy,
        "log_level": log_level,
    }
    app.admin.save_state(state)
    if protocol.installed and protocol.enabled and not app.protocols.reinstall(state, "telemt"):
        facade.error("Настройки сохранены, но Telemt не удалось применить.")
    else:
        facade.success("Расширенные настройки Telemt сохранены.")
    facade._pause()


def view_links(state, app) -> None:
    facade.clear()
    lines: list[str] = []
    for user in state.users:
        if not user.blocked:
            lines.append(f"{facade.BOLD}{user.email}{facade.NC}")
            lines.extend(
                f"  {facade.YELLOW}{link}{facade.NC}" for link in app.protocols.client_links(state, "telemt", user)
            )
    if not lines:
        facade.warn("Нет активных пользователей. Сначала создайте пользователя.")
    else:
        facade.panel("ССЫЛКИ TELEMT", lines, wrap=True)
    facade._pause()


def run_update(app) -> None:
    from hydra.plugins.telemt.plugin import GITHUB_REPO
    from hydra.utils.downloader import latest_release

    facade.clear()
    current = facade._get_installed_version(app) or "unknown"
    latest = latest_release(GITHUB_REPO)
    print(f"  Установленная версия: {current}")
    print(f"  Последняя stable:      {latest}")
    if current != latest and facade.confirm(f"Обновить Telemt до {latest}?"):
        if app.plugin_action("telemt", "update_binary"):
            facade.success("Telemt обновлён и проверен.")
        else:
            facade.error("Обновление не прошло; прежняя версия восстановлена.")
    facade._pause()


def view_logs(app) -> None:
    facade.clear()
    for command in (
        ["systemctl", "status", facade.SERVICE_NAME, "--no-pager"],
        ["journalctl", "-u", facade.SERVICE_NAME, "-n", "25", "--no-pager"],
    ):
        result = app.admin.run_command(command, capture_output=True, text=True)
        print(result.stdout or result.stderr)
    facade._pause()


def run_uninstall(state, app) -> None:
    facade.info("Удаляю Telemt и только его собственные артефакты...")
    if app.protocols.uninstall(state, "telemt"):
        facade.success("Telemt удалён.")
    else:
        facade.error("Не удалось удалить Telemt.")
