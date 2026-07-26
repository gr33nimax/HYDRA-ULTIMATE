"""Subscription server lifecycle menu controller."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    CYAN,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    title,
)


def install_sub_systemd_service(
    state: AppState,
    app: ApplicationService,
) -> bool:
    """Install the subscription unit through the application command port."""
    return app.admin.install_subscription_service(state)


def _obtain_cert_for_sub(
    state: AppState,
    app: ApplicationService,
) -> bool:
    sub_domain = getattr(state.network, "sub_domain", "")
    if not sub_domain:
        error("Сначала настройте домен подписок.")
        return False

    info(f"Получение SSL-сертификата для {sub_domain} через certbot...")
    result = app.admin.obtain_subscription_certificate(sub_domain)
    if result.ok:
        if result.code == "already_valid":
            success(f"Сертификат для {sub_domain} уже существует и действителен.")
        else:
            success("Сертификат успешно получен!")
        return True
    if result.code == "port_busy":
        error(
            "Не удалось освободить порт 80: "
            f"{result.message}: {result.detail}"
        )
    elif result.code == "certbot_install_failed":
        error("Не удалось установить certbot.")
    else:
        error("Ошибка работы certbot!")
    if result.detail:
        print(f"Вывод: {result.detail}")
    return False


def _subscription_status(
    state: AppState,
    app: ApplicationService,
) -> tuple[str, str, str, str, bool]:
    active = app.admin.unit_active("hydra-sub")
    status = (
        f"{GREEN}🟢 АКТИВЕН{NC}"
        if active
        else f"{RED}🔴 НЕ АКТИВЕН{NC}"
    )
    cert_file, _key_file = app.admin.subscription_certificate(state)
    cert_status = (
        f"{GREEN}Установлен ({cert_file}){NC}"
        if cert_file
        else f"{RED}Отсутствует (Необходим для HTTPS!){NC}"
    )
    sub_domain = getattr(state.network, "sub_domain", "")
    domain_status = (
        f"{CYAN}{sub_domain}{NC}"
        if sub_domain
        else f"{YELLOW}[НЕ НАСТРОЕН] (Используется IP){NC}"
    )
    host = app.admin.subscription_public_host(state)
    base_url = f"https://{host}"
    if not sub_domain:
        base_url += ":9443"
    return status, cert_status, domain_status, f"{base_url}/sub/<UUID>", bool(
        cert_file
    )


def _start_subscription_server(
    state: AppState,
    app: ApplicationService,
    *,
    has_certificate: bool,
) -> None:
    if not has_certificate:
        error(
            "Нельзя запустить сервер подписок без SSL-сертификата!"
        )
        prompt("Нажмите Enter")
        return
    install_sub_systemd_service(state, app)
    if app.admin.start_unit("hydra-sub"):
        success("Служба hydra-sub успешно запущена")
    else:
        error(
            "Не удалось запустить службу. "
            "Проверьте systemctl status hydra-sub"
        )
    prompt("Нажмите Enter")


def _stop_subscription_server(app: ApplicationService) -> None:
    if app.admin.stop_unit("hydra-sub"):
        app.admin.disable_unit("hydra-sub")
        success("Служба hydra-sub остановлена и отключена из автозапуска")
    else:
        error("Не удалось остановить службу")
    prompt("Нажмите Enter")


def _restart_subscription_server(
    app: ApplicationService,
    *,
    has_certificate: bool,
) -> None:
    if not has_certificate:
        error(
            "Нельзя перезапустить сервер подписок без SSL-сертификата!"
        )
        prompt("Нажмите Enter")
        return
    if app.admin.restart_unit("hydra-sub"):
        success("Служба hydra-sub успешно перезапущена")
    else:
        error("Не удалось перезапустить службу")
    prompt("Нажмите Enter")


def menu_subscription_server(state: AppState, app: ApplicationService):
    """Управление сервером подписок."""
    while True:
        clear()
        title("Сервер подписок")
        status, cert_status, domain_status, base_url, has_certificate = (
            _subscription_status(state, app)
        )
        sub_domain = getattr(state.network, "sub_domain", "")
        panel(
            "СОСТОЯНИЕ СЕРВЕРА",
            [
                kv("Статус службы:", status),
                kv("Домен подписок:", domain_status),
                kv("SSL-сертификат:", cert_status),
                kv("Базовый URL:", f"{CYAN}{base_url}{NC}"),
            ],
        )
        print()

        options = [
            (
                "1",
                "▶️  Запустить / Включить автозапуск",
                "Запустить службу hydra-sub",
            ),
            (
                "2",
                "⏹️  Остановить / Отключить автозапуск",
                "Остановить службу hydra-sub",
            ),
            ("3", "🔄 Перезапустить", "Перезапустить службу hydra-sub"),
            ("4", "🌐 Настроить домен подписок", ""),
        ]
        if sub_domain and not has_certificate:
            options.append(
                (
                    "5",
                    "🔑 Получить SSL-сертификат через Certbot",
                    "Standalone HTTP challenge",
                )
            )
        options.append(("0", "↩ Назад", ""))
        choice = menu(options, "СЕРВЕР ПОДПИСОК")

        if choice == "0":
            return
        if choice == "1":
            _start_subscription_server(
                state,
                app,
                has_certificate=has_certificate,
            )
        elif choice == "2":
            _stop_subscription_server(app)
        elif choice == "3":
            _restart_subscription_server(
                app,
                has_certificate=has_certificate,
            )
        elif choice == "4":
            new_domain = prompt(
                "Введите выделенный домен подписок "
                "(например, sub.example.com)",
                default=sub_domain,
            )
            app.admin.update_subscription_domain(state, new_domain)
            success(f"Домен подписок обновлён: {new_domain}")
            prompt("Нажмите Enter")
        elif choice == "5" and sub_domain and not has_certificate:
            if _obtain_cert_for_sub(state, app):
                app.admin.refresh_subscription_routing(state)
                app.admin.restart_unit("hydra-sub")
            prompt("Нажмите Enter")
