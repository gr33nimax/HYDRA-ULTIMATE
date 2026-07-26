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
from hydra.ui._menus.extended_protocol_awg_profiles import (
    _awg_generate_wizard_menu,
    _manage_awg_profiles,
    _rotate_awg_obfuscation,
)

def _menu_amneziawg(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    app = _application(app)
    
    while True:
        state = app.admin.load_state()
        clear()
        ps = _desired_state(state, p.meta.name)
        
        try:
            st = app.protocols.status(p.meta.name)
            profiles = (
                app.plugin_query(
                    "amneziawg",
                    "get_profiles",
                    state=state,
                )
                if st.installed
                else []
            )
            details = [("Профили", len(profiles))]
            details.extend(
                ("", f"{prof['label']} · {prof['interface']} · :{prof['port']} · {prof['preset']}")
                for prof in profiles
            )
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
                options.append(("3", "👤 Профили AWG", "Управление профилями (Desktop/Mobile)"))
                options.append(("4", "🔄 Ротация обфускации", "Ротировать параметры обфускации без downtime"))
                options.append(("5", "⚙️ Оптимизация VPS", "Hardware-aware sysctl/swap/NIC автотюнинг"))
                options.append(("6", "🎲 Генератор обфускации", "Пошаговый мастер генерации обфускации"))
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
            _manage_awg_profiles(state, p, app)
            
        elif choice == "4" and ps.installed and ps.enabled:
            _rotate_awg_obfuscation(state, p, app)
            
        elif choice == "5" and ps.installed and ps.enabled:
            _tune_awg_hardware(state, p, app)
            
        elif choice == "6" and ps.installed and ps.enabled:
            _awg_generate_wizard_menu(state, p, app)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = app.protocols.reinstall(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AmneziaWG?", default=False):
                app.protocols.uninstall(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")


def _tune_awg_hardware(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    del state, p
    app = _application(app)
    info("Анализ и оптимизация VPS...")
    report = app.admin.apply_network_tuning()
    
    lines = []
    
    # sysctl
    sysctl_changed = sum(1 for v in report["sysctl"].values() if v.get("changed"))
    lines.append("🎛️  Параметры sysctl:")
    if sysctl_changed:
        lines.append(f"     Применено {sysctl_changed} новых оптимизаций.")
    else:
        lines.append("     Все параметры sysctl уже оптимальны.")
        
    lines.append(
        "🚀 BBR: "
        + ("доступен" if report["bbr_available"] else "не поддерживается"),
    )
    lines.append(f"💾 Постоянный профиль: {report['config_path']}")
    lines.extend(f"⚠ {message}" for message in report["errors"][:5])
        
    panel("✅ VPS TUNING REPORT", lines)
    prompt("Нажмите Enter")
