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
    _desired_state,
    _show_plugin_clients,
)

def _menu_anytls(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)

    while True:
        # Keep the action label and subsequent save aligned with the state
        # committed by the preceding enable/disable transaction.
        state = app.admin.load_state()
        clear()
        ps = _desired_state(state, p.meta.name)

        # Статус
        try:
            st = app.protocols.status(p.meta.name)
            current_preset = app.plugin_query(
                "anytls",
                "get_current_preset",
                state=state,
            )
            from hydra.plugins.anytls.presets import get_preset
            preset_label = get_preset(current_preset)["label"]

            details = [("Обфускация", f"{BOLD}{CYAN}{preset_label}{NC}")]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )

        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "🔒 Обфускация трафика", f"Текущий режим: {preset_label}"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))

            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, protocol_menu_title(p.meta.name))

        if choice == "0":
            break

        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = app.protocols.install(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if app.protocols.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text(app=app))
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if app.protocols.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text(app=app))
            else:
                try:
                    if app.protocols.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text(app=app))
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")

        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p, app)

        elif choice == "3" and ps.installed and ps.enabled:
            _menu_anytls_obfuscation(state, p, app)

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = app.protocols.reinstall(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")

        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AnyTLS?", default=False):
                app.protocols.uninstall(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return


def _menu_anytls_obfuscation(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)
    from hydra.plugins.anytls.presets import list_presets, get_preset

    while True:
        clear()
        current_preset = app.plugin_query(
            "anytls",
            "get_current_preset",
            state=state,
        )
        presets = list_presets()
        preset_label = get_preset(current_preset)["label"]

        lines = [
            f"Текущий режим обфускации: {BOLD}{CYAN}{preset_label}{NC}",
            "",
            "Смена режима перегенерирует конфигурацию sing-box.",
            "Клиенты получат новые настройки при подключении/обновлении.",
        ]
        panel("🔒 ОБФУСКАЦИЯ ТРАФИКА ANYTLS", lines)
        print()

        options = []
        for idx, pr in enumerate(presets, 1):
            marker = "  "
            if pr["name"] == current_preset:
                marker = "• "
            options.append((str(idx), f"{marker}{pr['label']}", pr["description"]))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "ОБФУСКАЦИЯ ANYTLS")
        if choice == "0":
            break

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                preset_name = presets[idx]["name"]
                info(f"Применяю пресет обфускации {preset_name}...")
                if app.plugin_command(
                    state,
                    "anytls",
                    "set_preset",
                    preset_name=preset_name,
                ):
                    success(f"Пресет {preset_name} успешно применён!")
                else:
                    error(
                        _apply_error_text(
                            "Не удалось применить пресет",
                            app,
                        ),
                    )
                prompt("Нажмите Enter")
