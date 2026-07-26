"""Temporary password management for the qWDTT UI."""
from __future__ import annotations

import secrets
from datetime import datetime

from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.plugin_managers._wdtt_install import _client_link


def _device_count(entry: dict) -> int:
    device_ids = entry.get("device_ids", [])
    if device_ids:
        return len(device_ids)
    return 1 if entry.get("device_id") else 0


def _password_status(
    entry: dict,
    *,
    expired: bool,
) -> str:
    if entry.get("is_deactivated", False):
        return f"{facade.RED}отключён{facade.NC}"
    if expired:
        return f"{facade.YELLOW}истёк{facade.NC}"
    return f"{facade.GREEN}активен{facade.NC}"


def _password_lines(
    data: dict,
    app: facade.ApplicationService,
) -> list[str]:
    passwords = data.get("passwords", {})
    lines = [
        f"  Главный пароль:    {data.get('main_password', '—')}",
        f"  Временных паролей: {len(passwords)} / 10",
        "───────────────────────────────────────────────",
    ]
    active = [
        (
            password,
            entry,
            bool(
                entry.get("expires_at", 0) > 0
                and app.monitoring.now() > entry.get("expires_at", 0)
            ),
        )
        for password, entry in passwords.items()
        if entry
    ]
    if not active:
        lines.append(f"  {facade.YELLOW}Временных паролей нет.{facade.NC}")
        return lines
    lines.extend(
        [
            (
                f"  {facade.BOLD}{facade.CYAN}"
                f"{'Пароль':<18} {'Истекает':<14} {'Уст.':<6} "
                f"{'Статус'}{facade.NC}"
            ),
            "  " + "─" * 46,
        ],
    )
    for password, entry, expired in active:
        expires = entry.get("expires_at", 0)
        expires_label = (
            "бессрочный"
            if expires == 0
            else datetime.fromtimestamp(expires).strftime("%d.%m.%Y")
        )
        devices = _device_count(entry)
        maximum = entry.get("max_devices", 1) or 1
        status = _password_status(entry, expired=expired)
        lines.append(
            f"  {facade.CYAN}{password[:16]:<18}{facade.NC} "
            f"{facade.DIM}{expires_label:<14}{facade.NC} "
            f"{devices}/{maximum:<4} {status}",
        )
    return lines


def menu_passwords(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    while True:
        facade.clear()
        data = facade._load_passwords(app)
        passwords = data.get("passwords", {})
        facade.panel(
            "🔑 УПРАВЛЕНИЕ ВРЕМЕННЫМИ ПАРОЛЯМИ",
            _password_lines(data, app),
        )
        choice = facade.menu(
            [
                ("1", "➕ Создать временный пароль", ""),
                ("2", "🔗 Показать ссылку для пароля", ""),
                ("3", "❌ Удалить пароль", ""),
                ("0", "↩ Назад", ""),
            ],
            "ПАРОЛИ",
        )
        if choice == "0":
            return
        if choice == "1":
            facade._create_password_wizard(state, app)
        elif choice == "2":
            facade._show_password_link_wizard(state, passwords, app)
        elif choice == "3":
            facade._delete_password_wizard(passwords, app)


def _new_password_entry(
    app: facade.ApplicationService,
    *,
    days: int,
    max_devices: int,
    vk_hash: str,
) -> tuple[str, dict]:
    alphabet = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghjkmnpqrstuvwxyz"
        "23456789"
    )
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    expires_at = int(app.monitoring.now() + (days * 86_400))
    return password, {
        "device_ids": [],
        "max_devices": max_devices,
        "expires_at": expires_at,
        "down_bytes": 0,
        "up_bytes": 0,
        "vk_hash": vk_hash,
        "ports": "",
        "is_deactivated": False,
    }


def create_password(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Создание временного пароля")
    raw_days = facade.prompt("Дней действия (1-365)", default="30")
    days = int(raw_days) if raw_days.isdigit() else 30
    days = max(1, min(365, days))
    raw_devices = facade.prompt(
        "Макс. устройств (1-10)",
        default="1",
    )
    max_devices = int(raw_devices) if raw_devices.isdigit() else 1
    max_devices = max(1, min(10, max_devices))
    vk_hash = facade.prompt("VK хеш звонка (пропустить)").strip()

    data = facade._load_passwords(app)
    passwords = data.setdefault("passwords", {})
    if len(passwords) >= 10:
        facade.error("Превышен лимит: максимум 10 паролей!")
        facade.prompt("Нажмите Enter...")
        return
    password, entry = _new_password_entry(
        app,
        days=days,
        max_devices=max_devices,
        vk_hash=vk_hash,
    )
    passwords[password] = entry
    facade._save_passwords(data, app)
    facade._hot_reload(app)
    facade.success("Пароль успешно создан и применён!")

    server_ip = state.network.server_ip or facade._get_server_ip(app)
    protocol = facade.get_protocol(state, "wdtt")
    link = _client_link(
        server_ip,
        protocol.config.get("dtls_port", facade.DEFAULT_DTLS_PORT),
        password,
        vk_hash=vk_hash or "ВК_ХЕШ",
    )
    expires_label = datetime.fromtimestamp(
        entry["expires_at"],
    ).strftime("%d.%m.%Y")
    facade.panel(
        "ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ",
        [
            f"Временный пароль: {facade.YELLOW}{password}{facade.NC}",
            f"Действует до:     {expires_label}",
            f"Устройств:        {max_devices}",
            "",
            "Ссылка qwdtt:// для клиента:",
        ],
    )
    print(f"\n  {facade.YELLOW}{link}{facade.NC}\n")
    facade._save_link_to_file(
        link,
        f"link_{password[:8]}.txt",
        app,
    )
    facade.prompt("Нажмите Enter...")


def _password_selection(
    passwords: dict,
    *,
    title: str,
    include_hash: bool,
) -> str | None:
    password_list = list(passwords)
    options = []
    for index, password in enumerate(password_list, 1):
        detail = ""
        if include_hash:
            vk_hash = passwords[password].get("vk_hash", "") or "—"
            detail = f"хеш: {vk_hash[:15]}"
        options.append((str(index), password[:16], detail))
    options.append(("0", "Отмена", ""))
    choice = facade.menu(options, title)
    if choice == "0" or not choice:
        return None
    try:
        index = int(choice) - 1
    except ValueError:
        facade.error("Неверный ввод.")
        return None
    if not 0 <= index < len(password_list):
        return None
    return password_list[index]


def show_password_link(
    state: facade.AppState,
    passwords: dict,
    app: facade.ApplicationService,
) -> None:
    if not passwords:
        facade.warn("Нет созданных паролей.")
        facade.prompt("Нажмите Enter...")
        return
    facade.clear()
    facade.title("Показать ссылку для пароля")
    password = _password_selection(
        passwords,
        title="ВЫБЕРИТЕ ПАРОЛЬ",
        include_hash=True,
    )
    if password is None:
        return
    entry = passwords[password]
    server_ip = state.network.server_ip or facade._get_server_ip(app)
    protocol = facade.get_protocol(state, "wdtt")
    link = _client_link(
        server_ip,
        protocol.config.get("dtls_port", facade.DEFAULT_DTLS_PORT),
        password,
        vk_hash=entry.get("vk_hash", "") or "ВК_ХЕШ",
    )
    facade.panel(
        "ССЫЛКА ПОДКЛЮЧЕНИЯ",
        [
            f"Пароль: {facade.YELLOW}{password}{facade.NC}",
            "",
            "Ссылка для клиента:",
        ],
    )
    print(f"\n  {facade.YELLOW}{link}{facade.NC}\n")
    facade._save_link_to_file(
        link,
        f"link_{password[:8]}.txt",
        app,
    )
    facade.prompt("Нажмите Enter...")


def delete_password(
    passwords: dict,
    app: facade.ApplicationService,
) -> None:
    if not passwords:
        facade.warn("Нет созданных паролей.")
        facade.prompt("Нажмите Enter...")
        return
    facade.clear()
    facade.title("Удалить временный пароль")
    password = _password_selection(
        passwords,
        title="УДАЛИТЬ ПАРОЛЬ",
        include_hash=False,
    )
    if password and facade.confirm(f"Удалить пароль {password[:8]}...?"):
        data = facade._load_passwords(app)
        registry = data.get("passwords", {})
        if password in registry:
            del registry[password]
            facade._save_passwords(data, app)
            facade._hot_reload(app)
            facade.success("Пароль успешно удалён!")
    facade.prompt("Нажмите Enter...")
