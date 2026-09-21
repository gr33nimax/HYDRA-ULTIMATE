"""Hydra-facing Telemt install, update, logs and uninstall flows."""

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


# Exactly the three approved advanced controls. Each row names the one setting it
# writes and the single consequence the renderer actually produces.
_NETWORK_CHOICES = (
    ("1", "auto", "слушает 0.0.0.0"),
    ("2", "ipv4", "слушает 0.0.0.0"),
    ("3", "ipv6", "слушает ::"),
    ("4", "dual_stack", "слушает 0.0.0.0 и ::"),
)
_MIDDLE_PROXY_CHOICES = (
    ("1", "on", "трафик Telegram идёт через Middle Proxy"),
    ("2", "off", "прямой путь к Telegram"),
)
_LOG_CHOICES = (
    ("1", "normal", "обычные логи"),
    ("2", "debug", "подробная диагностика"),
)


def _consequence(choices: tuple[tuple[str, str, str], ...], value: object) -> str:
    return next((consequence for _key, candidate, consequence in choices if candidate == value), "")


def _advanced_rows(current) -> list[tuple[str, str, str]]:
    """Three rows: the stored value plus the one change the renderer makes."""
    middle_proxy = "on" if current.use_middle_proxy else "off"
    return [
        ("1", f"Сеть: {current.network} — {_consequence(_NETWORK_CHOICES, current.network)}", ""),
        ("2", f"MiddleProxy: {middle_proxy} — {_consequence(_MIDDLE_PROXY_CHOICES, middle_proxy)}", ""),
        ("3", f"Логи: {current.log_level} — {_consequence(_LOG_CHOICES, current.log_level)}", ""),
        ("0", "↩ Назад", ""),
    ]


def _pick(title: str, field: str, choices: tuple[tuple[str, str, str], ...]) -> str | None:
    """Offer only one row's validated values; ``None`` means cancelled."""
    options = [(key, f"{value} — {consequence}", "") for key, value, consequence in choices]
    options.append(("0", "↩ Отмена", ""))
    choice = facade.menu(options, title)
    for key, value, _consequence in choices:
        if key == choice:
            return value
    if choice != "0":
        facade.error(
            f"Недопустимое значение для {field}: {choice}. Допустимо: "
            + ", ".join(value for _key, value, _consequence in choices)
        )
    return None


def _save_advanced(state, app, protocol, **changes) -> None:
    """Persist one changed key, keeping the other advanced settings untouched."""
    advanced = protocol.config.get("advanced")
    if not isinstance(advanced, dict):
        advanced = {}
    advanced.update(changes)
    protocol.config["advanced"] = advanced
    app.admin.save_state(state)
    if protocol.installed and protocol.enabled and not app.protocols.reinstall(state, "telemt"):
        facade.error("Настройки сохранены, но Telemt не удалось применить.")
    else:
        facade.success("Расширенные настройки Telemt сохранены.")
    facade._pause()


def _edit_advanced(state, app, protocol, choice: str) -> None:
    if choice == "1":
        selected = _pick("СЕТЬ TELEMT", "network", _NETWORK_CHOICES)
        if selected is not None:
            _save_advanced(state, app, protocol, network=selected)
    elif choice == "2":
        selected = _pick("MIDDLEPROXY TELEMT", "use_middle_proxy", _MIDDLE_PROXY_CHOICES)
        if selected is not None:
            _save_advanced(state, app, protocol, use_middle_proxy=selected == "on")
    elif choice == "3":
        selected = _pick("ЛОГИ TELEMT", "log_level", _LOG_CHOICES)
        if selected is not None:
            _save_advanced(state, app, protocol, log_level=selected)


def run_advanced(state, app) -> None:
    """Repeating three-row advanced list; normal setup stays untouched."""
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
    while True:
        facade.clear()
        try:
            current = settings_from_state(state)
        except ValueError as exc:
            facade.error(str(exc))
            facade._pause()
            return
        choice = facade.menu(_advanced_rows(current), "РАСШИРЕННЫЕ НАСТРОЙКИ TELEMT")
        if choice == "0":
            return
        _edit_advanced(state, app, protocol, choice)


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
