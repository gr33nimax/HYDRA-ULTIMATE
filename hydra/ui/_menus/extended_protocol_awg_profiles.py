"""Controllers for extended transport menus and client status."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)

from hydra.ui._menus.extended_protocol_common import (
    _application,
    _apply_error_text,
)
from hydra.ui._menus.extended_protocol_awg_wizard import _awg_generate_wizard

def _manage_awg_profiles(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)
    while True:
        clear()
        profiles = app.plugin_query(
            "amneziawg",
            "get_profiles",
            state=state,
        )
        lines = []
        for i, prof in enumerate(profiles, 1):
            lines.append(f"  {i}. {prof['label']} ({prof['interface']}) on port {prof['port']}")
            lines.append(f"     Preset: {prof['preset']}")
            lines.append(f"     Network: {prof['network']}")
        panel("📁 УПРАВЛЕНИЕ ПРОФИЛЯМИ AWG", lines)

        options = []
        has_mobile = any(prof["name"] == "mobile" for prof in profiles)
        if not has_mobile:
            options.append(("1", "➕ Добавить мобильный профиль", "Создать профиль с мобильным пресетом"))
        else:
            options.append(("2", "❌ Удалить мобильный профиль", "Удалить профиль с мобильным пресетом"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "AWG PROFILES")
        if choice == "0":
            break

        elif choice == "1" and not has_mobile:
            res = _awg_generate_wizard(state, p)
            if res:
                strategy, carrier = res
                carrier_str = carrier if carrier else "generic"
                preset_name = f"{strategy}:{carrier_str}"
                info(f"Создание профиля с пресетом {preset_name}...")
                if app.plugin_command(
                    state,
                    "amneziawg",
                    "add_profile",
                    name="mobile",
                    preset=preset_name,
                ):
                    success("Мобильный профиль успешно создан!")
                else:
                    error("Не удалось создать мобильный профиль")
                prompt("Нажмите Enter")

        elif choice == "2" and has_mobile:
            if confirm("Удалить мобильный профиль?", default=False):
                info("Удаление...")
                if app.plugin_command(
                    state,
                    "amneziawg",
                    "remove_profile",
                    name="mobile",
                ):
                    success("Профиль удален")
                else:
                    error("Ошибка удаления")
                prompt("Нажмите Enter")


def _rotate_awg_obfuscation(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)
    profiles = app.plugin_query(
        "amneziawg",
        "get_profiles",
        state=state,
    )
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Ротировать {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))

    choice = menu(options, "РОТАЦИЯ ОБФУСКАЦИИ")
    if choice == "0" or not choice.isdigit():
        return

    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]

        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if app.plugin_command(
                state,
                "amneziawg",
                "rotate_obfuscation",
                profile=prof["name"],
                preset=preset_name,
            ):
                success("Параметры успешно ротированы без downtime!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error("Ошибка ротации")
            prompt("Нажмите Enter")


def _awg_generate_wizard_menu(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)
    profiles = app.plugin_query(
        "amneziawg",
        "get_profiles",
        state=state,
    )
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Применить к {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))

    choice = menu(options, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ ГЕНЕРАЦИИ")
    if choice == "0" or not choice.isdigit():
        return

    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]
        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if app.plugin_command(
                state,
                "amneziawg",
                "rotate_obfuscation",
                profile=prof["name"],
                preset=preset_name,
            ):
                success("Параметры успешно применены!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error(_apply_error_text("Ошибка применения параметров", app))
            prompt("Нажмите Enter")
