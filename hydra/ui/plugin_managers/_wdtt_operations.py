"""Runtime operations for the qWDTT UI."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.plugin_managers._wdtt_install import _client_link


def show_main_link(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    protocol = facade.get_protocol(state, "wdtt")
    pool_link = str(app.plugin_query("wdtt", "qwdtt_call_pool_link"))
    server_ip = state.network.server_ip or facade._get_server_ip(app)
    link = _client_link(
        server_ip,
        protocol.config.get("dtls_port", facade.DEFAULT_DTLS_PORT),
        protocol.config.get("main_password", ""),
        vk_hash="ВК_ХЕШ",
    )
    if pool_link:
        link = pool_link
    instructions = (
        ["Ссылка содержит актуальные VK-хеши и главный пароль."]
        if pool_link
        else [
            "Замените ВК_ХЕШ на хеш из ссылки "
            "vk.com/call/join/ХЕШ",
        ]
    )
    facade.panel(
        "ГЛАВНАЯ ССЫЛКА",
        ["Ссылка qwdtt:// (Главный пароль):", *instructions],
    )
    print(f"\n  {facade.YELLOW}{link}{facade.NC}\n")
    facade._save_link_to_file(link, "qwdtt_link.txt", app)
    facade.prompt("Нажмите Enter...")


def restart_service(app: facade.ApplicationService) -> None:
    facade.info("Перезапускаю wdtt-server...")
    app.admin.restart_unit(facade.SERVICE_NAME)
    app.monitoring.sleep(1.5)
    if app.admin.unit_active(facade.SERVICE_NAME):
        facade.success("Сервис успешно перезапущен!")
    else:
        facade.error(
            "Ошибка перезапуска сервиса. Проверьте статус/логи.",
        )
    facade.prompt("Нажмите Enter...")


def show_status_logs(app: facade.ApplicationService) -> None:
    facade.clear()
    facade.title("Статус и Логи qWDTT")
    status = facade._diagnostic_output(
        app,
        [
            "systemctl",
            "status",
            facade.SERVICE_NAME,
            "--no-pager",
            "--full",
        ],
        "Нет данных о состоянии службы.",
    )
    print(
        f"\n{facade.CYAN}"
        f"=== systemctl status wdtt ==={facade.NC}\n",
    )
    print(status)
    print(
        f"\n{facade.CYAN}"
        f"=== Последние 20 строк journalctl ==={facade.NC}\n",
    )
    journal = facade._diagnostic_output(
        app,
        [
            "journalctl",
            "-u",
            facade.SERVICE_NAME,
            "-n",
            "20",
            "--no-pager",
            "--output=short-iso",
        ],
        "В журнале пока нет записей.",
    )
    print(journal)
    facade.prompt("Нажмите Enter, чтобы вернуться")


def uninstall_wdtt(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Удаление qWDTT")
    facade.warn("Это полностью удалит qWDTT с вашего сервера.")
    if not facade.confirm("Вы уверены, что хотите удалить qWDTT?"):
        return
    facade.info("Удаляю...")
    if app.protocols.uninstall(state, "wdtt"):
        facade.success("qWDTT успешно удалён с сервера.")
    else:
        facade.error("Ошибка при удалении плагина.")
    facade.prompt("Нажмите Enter...")
