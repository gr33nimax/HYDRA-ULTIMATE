"""Main qWDTT manager menu."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _render_status(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> bool:
    protocol = facade.get_protocol(state, "wdtt")
    runtime = app.plugin_query("wdtt", "observe_runtime")
    details: list[tuple[str, object]] = []
    if runtime.installed:
        details.append(("WG порт", runtime.wg_port))
        passwords = facade._load_passwords(app)
        details.extend(
            [
                ("Паролей", len(passwords.get("passwords", {}))),
                ("Устройств", len(passwords.get("devices", {}))),
            ],
        )
        telegram = "✓ настроен" if passwords.get("bot_token") else "не настроен"
        color = facade.GREEN if passwords.get("bot_token") else facade.DIM
        details.append(("Telegram", f"{color}{telegram}{facade.NC}"))
        headless = app.plugin_query(
            "wdtt",
            "headless_creator_status",
            state=state,
        )
        if isinstance(headless, dict) and headless.get("configured"):
            calls = int(headless.get("call_count", 0))
            refreshed = headless.get("refreshed_at") or "ожидает запуска"
            details.append(("Headless creator", f"{calls}/4 звонка"))
            details.append(("Обновлено", refreshed))
    facade.protocol_status_panel(
        "wdtt",
        installed=runtime.installed,
        enabled=protocol.enabled,
        running=runtime.running,
        port=runtime.dtls_port if runtime.installed else None,
        details=details,
    )
    return runtime.installed


def _options(installed: bool) -> list[tuple[str, str, str]]:
    options: list[tuple[str, str, str]] = []
    if not installed:
        options.append(
            (
                "1",
                "🚀 Установить qWDTT",
                "Сборка wdtt-server, настройка службы и NAT",
            ),
        )
    else:
        options.extend(
            [
                (
                    "1",
                    "🚀 Переустановить",
                    "Пересобрать и переустановить службу",
                ),
                (
                    "2",
                    "🔑 Управление паролями",
                    "Просмотр, добавление и удаление паролей",
                ),
                (
                    "3",
                    "🔗 Показать ссылку (главный пароль)",
                    "qwdtt:// ссылка администратора",
                ),
                (
                    "4",
                    "🔄 Перезапустить сервис",
                    "Выполнить systemctl restart wdtt",
                ),
                (
                    "5",
                    "📊 Статус / логи",
                    "Просмотр логов systemd и journalctl",
                ),
                (
                    "6",
                    "🤖 Настроить VK headless creator",
                    "Установить creator, создать четыре звонка и включить суточное обновление",
                ),
                (
                    "9",
                    "❌ Удалить qWDTT",
                    "Полное удаление бинарников, конфигов и правил",
                ),
            ],
        )
    options.extend(
        [
            (
                "G",
                "📖 Гайд",
                "Руководство по установке, VK-хешам и боту",
            ),
            ("0", "↩ Назад", ""),
        ],
    )
    return options


def _dispatch(
    choice: str,
    state: facade.AppState,
    app: facade.ApplicationService,
    *,
    installed: bool,
) -> bool:
    if choice == "0":
        return False
    if choice == "1":
        facade._run_install(state, app)
    elif choice == "2" and installed:
        facade._passwords_menu(state, app)
    elif choice == "3" and installed:
        facade._show_main_link(state, app)
    elif choice == "4" and installed:
        facade._restart_service(app)
    elif choice == "5" and installed:
        facade._show_status_logs(app)
    elif choice == "6" and installed:
        facade._setup_headless_creator(state, app)
    elif choice == "9" and installed:
        facade._uninstall_wdtt(state, app)
    elif choice.upper() == "G":
        facade._show_guide()
    return True


def run(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    while True:
        facade.clear()
        installed = _render_status(state, app)
        choice = facade.menu(
            _options(installed),
            facade.protocol_menu_title("wdtt"),
        )
        if not _dispatch(
            choice,
            state,
            app,
            installed=installed,
        ):
            return
