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

def _menu_trusttunnel(
    state: AppState,
    p,
    app: ApplicationService | None = None,
):
    """Подменю управления TrustTunnel."""
    app = _application(app)

    while True:
        clear()
        ps = _desired_state(state, p.meta.name)

        try:
            st = app.protocols.status(p.meta.name)
            domain = ps.config.get("domain", "") if ps.config else ""
            transport = ps.config.get("transport", "tcp") if ps.config else "tcp"
            transport_labels = {
                "tcp": "HTTP/2 TCP",
                "quic": "QUIC UDP",
                "both": "HTTP/2 + QUIC",
            }
            details = [
                ("Домен", domain),
                ("Транспорт", transport_labels.get(transport, "HTTP/2 TCP")),
            ]
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
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))

            options.append(("3", "🌐 Транспорт", "HTTP/2 TCP / QUIC UDP / оба"))
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

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = app.protocols.reinstall(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")

        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить TrustTunnel?", default=False):
                app.protocols.uninstall(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return

        elif choice == "3" and ps.installed:
            current = ps.config.get("transport", "tcp")
            mode_choice = menu([
                ("1", "HTTP/2 TCP", "Стабильный режим по умолчанию"),
                ("2", "QUIC UDP", "Экспериментальный HTTP/3 через Caddy UDP proxy"),
                ("3", "HTTP/2 + QUIC", "Две клиентские ссылки"),
                ("0", "Отмена", "Оставить текущий режим"),
            ], "ТРАНСПОРТ TRUSTTUNNEL")
            selected = {"1": "tcp", "2": "quic", "3": "both"}.get(mode_choice)
            if selected is not None:
                if selected == current:
                    info("Этот транспорт уже выбран")
                elif app.plugin_command(
                    state,
                    "trusttunnel",
                    "set_transport",
                    transport=selected,
                ):
                    success("Транспорт изменён")
                else:
                    error(
                        "Не удалось применить транспорт. Проверьте конфликт UDP/443, "
                        "сертификат и журнал sing-box; прежняя конфигурация восстановлена."
                    )
                prompt("Нажмите Enter")
