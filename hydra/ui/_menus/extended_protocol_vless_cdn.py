"""Меню протокола «VLESS через CDN»: установка, профиль клиента, страница."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.vless_cdn import client as cdn_client
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME
from hydra.services.application import ApplicationService
from hydra.services.vless_cdn_install import install_protocol
from hydra.services.vless_cdn_site import (
    install_site_timer,
    refresh_site,
    remove_site_timer,
)
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    NC,
    PANEL_W,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)

from hydra.ui._menus.extended_protocol_common import _application, _desired_state
from hydra.ui._menus.protocol_activation import run_lifecycle_action


def _install(state: AppState, plugin: object, app: ApplicationService) -> None:
    """Спросить два имени, выпустить сертификат и поставить обновление страницы."""
    cdn_domain = prompt("CDN-домен (который вводит клиент):").strip()
    origin_host = prompt("Origin-имя (под которым CDN ходит на сервер):").strip()

    outcome = install_protocol(state, cdn_domain=cdn_domain, origin_host=origin_host)
    if not outcome.ok:
        error(outcome.detail)
        prompt("Нажмите Enter")
        return

    info("Сохраняю состояние...")
    if not app.admin.save_state(state):
        error("Не удалось сохранить состояние")
        prompt("Нажмите Enter")
        return

    if not install_site_timer():
        error("Страница установлена, но таймер обновления поставить не удалось")
        prompt("Нажмите Enter")
        return

    try:
        refresh_site(state)
    except Exception as exc:
        error(f"Страница не обновилась: {exc}")
        prompt("Нажмите Enter")
        return

    success("Установлено")
    for line in outcome.lines():
        info(line)
    info("Настройте на стороне CDN: origin_protocol=https и origin SNI как выше.")
    prompt("Нажмите Enter")


def _show_profile(state: AppState, plugin: object) -> None:
    """Показать клиенту, куда подключаться, вместе с честной оговоркой."""
    desired = _desired_state(state, PROTOCOL_NAME)
    try:
        view = cdn_client.client_view(
            _first_user(state),
            desired.config,
        )
        body = [
            f"Сервер: {BOLD}{view['server']}:{view['port']}{NC}",
            f"XHTTP путь: {view['path']}",
            f"Режим: {view['mode']}",
            f"Шифрование: {view['encryption_mode']}",
        ]
        panel("Клиент", body, width=PANEL_W, wrap=True)
        info(str(view["share_note"]))
        info("")
        info(cdn_client.profile(_first_user(state), desired.config))
    except Exception as exc:
        error(f"Профиль недоступен: {exc}")
    prompt("Нажмите Enter")


def _refresh_now(state: AppState) -> None:
    try:
        target = refresh_site(state)
    except Exception as exc:
        error(f"Страница не обновилась: {exc}")
        prompt("Нажмите Enter")
        return
    success(f"Страница обновлена: {target}")
    prompt("Нажмите Enter")


def _first_user(state: AppState):
    """Первый активный пользователь: профиль выдаётся конкретному человеку."""
    for user in state.users:
        if not user.blocked:
            return user
    raise ValueError("нет ни одного активного пользователя")


def _menu_vless_cdn(
    state: AppState,
    plugin: object,
    app: ApplicationService | None = None,
) -> None:
    """Меню протокола: два имени, профиль клиента и страница-прикрытие."""
    app = _application(app)

    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, PROTOCOL_NAME)
        clear()

        config = desired.config
        details = [
            ("CDN-домен", str(config.get("cdn_domain", "") or "—")),
            ("Origin-имя", str(config.get("origin_host", "") or "—")),
            ("XHTTP путь", str(config.get("xhttp_path", "") or "—")),
            ("Порт ядра", str(config.get("core_port", 0) or "—")),
            ("Сертификат", str(config.get("cert_file", "") or "—")),
            ("Регион", str(config.get("region_city", "") or "—")),
        ]
        protocol_status_panel(
            PROTOCOL_NAME,
            installed=bool(config.get("cert_file")),
            enabled=desired.enabled,
            running=bool(desired.enabled and config.get("cert_file")),
            port=int(config.get("core_port", 0) or 0),
            details=details,
            display_name=plugin.meta.display_name,
        )

        options: list[tuple[str, str, str]] = []
        if config.get("cert_file"):
            options.append(
                (
                    "1",
                    "⏸️  Выключить" if desired.enabled else "▶️  Включить",
                    "Отключить протокол" if desired.enabled else "Активировать протокол",
                ),
            )
            options.extend(
                [
                    ("2", "🌐 Профиль клиента", "Куда подключается клиент и ссылка"),
                    ("3", "🖼  Обновить страницу", "Перегенерировать сайт сейчас"),
                    ("8", "🔄 Переустановить", "Заменить домены и выпустить сертификат заново"),
                    ("9", "❌ Удалить", "Протокол, страница и таймер"),
                ],
            )
        else:
            options.append(
                ("1", "🔧 Установить", "Спросить CDN-домен и origin-имя"),
            )

        options.append(("0", "↩ Назад", ""))
        choice = menu(
            options,
            protocol_menu_title(PROTOCOL_NAME, plugin.meta.display_name),
        )

        if choice == "0":
            return
        if choice == "1" and not config.get("cert_file"):
            _install(state, plugin, app)
        elif choice == "1":
            run_lifecycle_action(
                state,
                plugin,
                desired,
                app,
                ask=prompt,
                report_error=error,
                report_info=info,
                report_success=success,
                pause=prompt,
            )
        elif choice == "2":
            _show_profile(state, plugin)
        elif choice == "3":
            _refresh_now(state)
        elif choice == "8":
            if confirm("Переустановить протокол с новыми доменами?", default=False):
                _install(state, plugin, app)
        elif choice == "9":
            if not confirm("Удалить протокол, страницу и таймер?", default=False):
                continue
            remove_site_timer()
            if app.protocols.uninstall(state, PROTOCOL_NAME):
                success("Удалено")
                prompt("Нажмите Enter")
                return
            error("Ошибка удаления")
            prompt("Нажмите Enter")


__all__ = ["_menu_vless_cdn"]
