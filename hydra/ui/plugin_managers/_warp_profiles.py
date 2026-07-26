"""Relay-profile interactions for the WARP manager facade."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BLUE,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)

def _menu_geo_profiles(
    state: AppState,
    ps,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        observation = facade._warp_observation(app)
        profile_directory = str(observation.get("profile_directory", ""))
        profile_rows = sorted(
            (
                row
                for row in observation.get("profiles", [])
                if isinstance(row, dict) and row.get("name")
            ),
            key=lambda row: str(row["name"]),
        )
        profiles = [str(row["name"]) for row in profile_rows]
        list_targets = ps.config.setdefault("list_targets", {})

        status_lines = [
            f"  {BOLD}Каталог профилей:{NC} {profile_directory}",
            f"  Для добавления нового релея загрузите .conf файл в этот каталог.",
            "  " + "─" * 60
        ]

        if not profiles:
            status_lines.append(f"  {YELLOW}Нет обнаруженных профилей релеев.{NC}")
            status_lines.append("  Доступен только стандартный дефолтный WARP.")
        else:
            for idx, row in enumerate(profile_rows, 1):
                name = str(row["name"])
                is_amnezia = bool(row.get("is_amnezia"))
                h4_warning = bool(row.get("h4_warning"))

                type_str = f"{CYAN}AmneziaWG{NC}" if is_amnezia else f"{BLUE}WireGuard{NC}"
                warn_str = f" {RED}(⚠ H4 > 255){NC}" if h4_warning else ""

                mapped_lists = []
                for k, target in list_targets.items():
                    if target == f"warp_{name}":
                        list_name = k.split(":", 1)[1]
                        mapped_lists.append(list_name)

                routes_str = f"Направлены списки: {', '.join(mapped_lists)}" if mapped_lists else "Нет привязанных списков"

                status_lines.append(
                    f"  {idx}. {BOLD}warp_{name:<12}{NC} [{type_str}]{warn_str} "
                    f"│ {DIM}{routes_str}{NC}"
                )

        panel("⚙️ УПРАВЛЕНИЕ ПРОФИЛЯМИ РЕЛЕЕВ", status_lines)

        options = []
        if profiles:
            options.append(("1", "🗑️  Удалить файл профиля релея", "Удалить .conf файл с диска"))
        options.append(("2", "💡 Показать инструкцию по установке", "Как получить конфиг и скопировать на сервер"))
        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "ПРОФИЛИ РЕЛЕЕВ")
        if choice == "0":
            break

        elif choice == "1" and profiles:
            opts_prof = []
            for i, name in enumerate(profiles, start=1):
                opts_prof.append((str(i), name, f"УДАЛИТЬ {name}.conf"))
            opts_prof.append(("0", "Назад", ""))

            p_choice = menu(opts_prof, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ УДАЛЕНИЯ")
            if p_choice == "0" or not p_choice.isdigit():
                continue

            idx = int(p_choice) - 1
            if 0 <= idx < len(profiles):
                name = profiles[idx]
                if confirm(f"Вы действительно хотите удалить релей '{name}' ({name}.conf)?", default=False):
                    app.plugin_action(
                        "warp",
                        "delete_local_profile",
                        name=name,
                    )
                    keys_to_clean = [k for k, target in list_targets.items() if target == f"warp_{name}"]
                    for k in keys_to_clean:
                        list_targets[k] = "none"
                    app.admin.save_state(state)
                    success(f"Релей warp_{name} успешно удален.")
                    if ps.enabled:
                        info("Обновляю конфигурацию Sing-Box...")
                        if not app.apply(state):
                            error("Ошибка применения нового конфига.")
                            facade._show_diagnostic_info(app)
                prompt("Нажмите Enter для продолжения")

        elif choice == "2":
            clear()
            lines = [
                f"  {BOLD}Как настроить гео-WARP релей:{NC}",
                "",
                "  1. Сгенерируйте профиль через Telegram-бота",
                f"     {GREEN}@warp_generator_bot{NC} или сайт.",
                "  2. Скачайте полученный .conf файл",
                "     (например, 'russia.conf' или 'finland.conf').",
                "  3. Подключитесь к VPS по SFTP (FileZilla, WinSCP и др.).",
                f"  4. Скопируйте файл в каталог на сервере:",
                f"     {GREEN}{profile_directory}{NC}",
                "     Имя файла (без .conf) будет именем релея.",
                "  5. Свяжите нужные списки правил с этим релеем в меню",
                "     'Настройка маршрутизации'.",
                "  6. Включите WARP для применения конфигурации.",
                "",
                f"  {BOLD}Важно:{NC} Имя файла должно содержать только",
                "  английские буквы, цифры и дефис.",
                "  Пример: russia.conf, finland.conf, nl-amsterdam.conf",
            ]
            panel("ИНСТРУКЦИЯ ПО УСТАНОВКЕ", lines)
            prompt("Нажмите Enter, чтобы вернуться")
