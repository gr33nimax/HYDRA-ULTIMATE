"""Interactive qWDTT installation flow."""
from __future__ import annotations

import secrets

from hydra.ui.plugin_managers._facade_bridge import facade


def _preserve_existing(app: facade.ApplicationService) -> bool | None:
    if not app.protocols.status("wdtt").installed:
        return True
    facade.warn("qWDTT уже установлен.")
    choice = facade.menu(
        [
            (
                "1",
                "Переустановить с сохранением паролей и конфига",
                "",
            ),
            (
                "2",
                "Установить полностью заново (сбросить пароли)",
                "",
            ),
            ("0", "Отмена", ""),
        ],
        "ПЕРЕУСТАНОВКА",
    )
    if choice == "0" or not choice:
        return None
    return choice != "2"


def _existing_settings(
    app: facade.ApplicationService,
    *,
    preserve: bool,
) -> dict[str, object]:
    settings: dict[str, object] = {
        "main_password": "",
        "dtls_port": facade.DEFAULT_DTLS_PORT,
        "wg_port": facade.DEFAULT_WG_PORT,
        "admin_id": "",
        "bot_token": "",
    }
    if not preserve:
        return settings
    runtime = app.plugin_query("wdtt", "observe_runtime")
    passwords = facade._load_passwords(app)
    settings.update(
        {
            "main_password": passwords.get(
                "main_password",
                runtime.main_password,
            ),
            "dtls_port": runtime.dtls_port,
            "wg_port": runtime.wg_port,
            "admin_id": passwords.get("admin_id", runtime.admin_id),
            "bot_token": passwords.get("bot_token", runtime.bot_token),
        },
    )
    return settings


def _port(label: str, default: object) -> int:
    value = facade.prompt(label, default=str(default))
    return int(value) if value.isdigit() else int(default)


def _collect_settings(current: dict[str, object]) -> dict[str, object] | None:
    main_password = facade.prompt(
        "Главный пароль (оставьте пустым для автогенерации)",
        default=str(current["main_password"]),
    )
    if not main_password:
        main_password = (
            str(current["main_password"])
            or secrets.token_hex(8)
        )
    dtls_port = _port(
        "UDP порт DTLS (входящий от TURN-сервера)",
        current["dtls_port"],
    )
    wg_port = _port(
        "UDP порт WireGuard (внутренний)",
        current["wg_port"],
    )
    if dtls_port == wg_port:
        facade.error("Порты DTLS и WireGuard не должны совпадать!")
        facade.prompt("Нажмите Enter...")
        return None
    admin_id = facade.prompt(
        "Telegram Admin ID (для управления паролями, пропустить)",
        default=str(current["admin_id"] or ""),
    )
    bot_token = ""
    if admin_id:
        bot_token = facade.prompt(
            "Telegram Bot Token (для управления паролями, пропустить)",
            default=str(current["bot_token"] or ""),
        )
    return {
        "main_password": main_password,
        "dtls_port": dtls_port,
        "wg_port": wg_port,
        "admin_id": admin_id,
        "bot_token": bot_token,
    }


def _client_link(
    server_ip: str,
    dtls_port: int,
    password: str,
    *,
    vk_hash: str = "ВК_ХЕШ_ЗВОНКА",
) -> str:
    return (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_hash}"
        f"&workers=16&port={facade.LOCAL_TUN_PORT}"
        f"&pass={password}"
    )


def run_install(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Установка / Настройка qWDTT")
    preserve = _preserve_existing(app)
    if preserve is None:
        return
    current = _existing_settings(app, preserve=preserve)
    print(
        f"\n  {facade.CYAN}"
        f"--- Настройка портов и паролей ---{facade.NC}\n",
    )
    settings = _collect_settings(current)
    if settings is None:
        return
    protocol = facade.get_protocol(state, "wdtt")
    protocol.config.update(settings)
    app.admin.save_state(state)
    facade.info(
        "Сборка wdtt-server из исходников "
        "(это может занять 1-2 минуты)...",
    )
    if not app.protocols.install(state, "wdtt"):
        facade.error("Не удалось скомпилировать или запустить wdtt-server.")
        facade.prompt("Нажмите Enter...")
        return
    app.protocols.enable(state, "wdtt")
    facade.success("Установка и запуск qWDTT завершены успешно!")
    server_ip = state.network.server_ip or facade._get_server_ip(app)
    link = _client_link(
        server_ip,
        int(settings["dtls_port"]),
        str(settings["main_password"]),
    )
    facade.panel(
        "БЫСТРАЯ ССЫЛКА",
        [
            "Ссылка qwdtt:// для импорта в Android-клиент:",
            "Замените ВК_ХЕШ_ЗВОНКА на хеш "
            "из ссылки vk.com/call/join/ХЕШ",
        ],
    )
    print(f"\n  {facade.YELLOW}{link}{facade.NC}\n")
    facade._save_link_to_file(link, "qwdtt_link.txt", app)
    facade.prompt("Нажмите Enter...")
