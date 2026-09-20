"""Small, Hydra-native Telemt manager menu."""

from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _ensure_protocol_state(state):
    protocol = state.protocols.setdefault("telemt", facade.PluginState())
    if not protocol.config:
        protocol.config = {
            "settings_version": 1,
            "port": facade.DEFAULT_PORT,
            "tls_domain": state.network.domain or "google.com",
            "advanced": {
                "network": "auto",
                "use_middle_proxy": False,
                "log_level": "normal",
            },
        }
    return protocol


def _render_status(protocol, app):
    plugin_status = app.protocols.status("telemt")
    installed = plugin_status.installed
    facade.protocol_status_panel(
        "telemt",
        installed=installed,
        enabled=protocol.enabled,
        running=plugin_status.running,
        port=protocol.config.get("port", facade.DEFAULT_PORT),
        details=[
            ("Версия", facade._get_installed_version(app) if installed else None),
            ("TLS-домен", protocol.config.get("tls_domain", "—")),
        ],
    )
    return installed


def _menu_options(*, installed, enabled):
    """Offer only the actions that make sense in the current install state."""
    if not installed:
        return [
            ("1", "Установить Telemt", "Порт и TLS-домен"),
            ("-", "", ""),
            ("0", "Назад", ""),
        ]
    return [
        ("1", "Перенастроить", "Сменить порт и TLS-домен"),
        ("2", "Расширенные настройки", "Сеть, MiddleProxy и логи"),
        ("3", "Показать ссылки", "Ссылки активных пользователей"),
        ("4", "Перезапустить сервис", "Перезапуск telemt"),
        ("5", "Проверить и обновить", "Ручное обновление с rollback"),
        ("6", "Статус и логи", "systemd и последние журналы"),
        ("7", "Отключить Telemt" if enabled else "Включить Telemt", "Изменить состояние службы"),
        ("9", f"{facade.RED}Удалить Telemt{facade.NC}", "Только артефакты Telemt"),
        ("-", "", ""),
        ("0", "Назад", ""),
    ]


def _toggle(state, app, protocol, *, installed):
    target_enabled = not protocol.enabled
    if target_enabled and not installed:
        facade.warn("Сначала установите Telemt.")
    elif not target_enabled and not facade.confirm("Отключить Telemt?"):
        return
    elif facade._set_telemt_enabled(state, target_enabled, app):
        facade.success("Telemt включён." if target_enabled else "Telemt отключён.")
    else:
        facade.error(app.apply_error() or "Не удалось изменить состояние Telemt.")
    facade._pause()


def _dispatch(choice, state, app, protocol, *, installed):
    choice = choice.lower()
    if choice == "0":
        return False
    if choice == "1":
        facade._run_install(state, app)
    elif not installed:
        facade.warn("Сначала установите Telemt.")
        facade._pause()
    elif choice == "2":
        facade._run_advanced(state, app)
    elif choice == "3":
        facade._view_links(state, app)
    elif choice == "4":
        app.admin.restart_unit(facade.SERVICE_NAME)
    elif choice == "5":
        facade._run_update(app)
    elif choice == "6":
        facade._view_logs(app)
    elif choice == "7":
        _toggle(state, app, protocol, installed=installed)
    elif choice == "9" and facade.confirm("Удалить Telemt?"):
        facade._run_uninstall(state, app)
    return True


def run(state, app):
    protocol = _ensure_protocol_state(state)
    while True:
        facade.clear()
        installed = _render_status(protocol, app)
        choice = facade.menu(
            _menu_options(installed=installed, enabled=protocol.enabled),
            facade.protocol_menu_title("telemt"),
        )
        try:
            if not _dispatch(choice, state, app, protocol, installed=installed):
                return
        except facade._Cancelled:
            facade.info("Операция отменена.")
            facade._pause()
        except Exception as exc:
            facade.error(f"Неожиданная ошибка: {exc}")
            facade._pause()
