"""Whitelist interactions for the Fail2ban TUI controller."""
from __future__ import annotations

import ipaddress

from hydra.core.state_models import AppState, get_protocol
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    CYAN,
    DIM,
    NC,
    clear,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
    warn,
)


def _add(
    state: AppState,
    app: ApplicationService,
    whitelist: list[str],
) -> None:
    network = prompt(
        "Введите IP или подсеть "
        "(например, 192.168.1.100 или 10.0.0.0/24)",
    ).strip()
    if not network:
        warn("Ввод пуст.")
        prompt("Нажмите Enter для продолжения")
        return
    try:
        if "/" in network:
            ipaddress.ip_network(network, strict=False)
        else:
            ipaddress.ip_address(network)
    except ValueError:
        error("Некорректный формат IP-адреса или подсети!")
        prompt("Нажмите Enter для продолжения")
        return
    if network in whitelist:
        warn("Этот IP/подсеть уже есть в списке.")
    else:
        info("Применяю конфигурацию whitelist...")
        if app.plugin_command(
            state,
            "fail2ban",
            "add_whitelist",
            network=network,
        ):
            success(f"Добавлен в whitelist и применен: {network}")
        else:
            warn(
                f"Добавлен в whitelist: {network}, "
                "но Fail2ban не смог применить конфигурацию автоматически",
            )
    prompt("Нажмите Enter для продолжения")


def _remove(
    state: AppState,
    app: ApplicationService,
    whitelist: list[str],
) -> None:
    if not whitelist:
        error("Список пуст, нечего удалять.")
        prompt("Нажмите Enter...")
        return
    options = [
        (str(index), network, "")
        for index, network in enumerate(whitelist, 1)
    ]
    options.append(("0", "Отмена", ""))
    choice = menu(options, "УДАЛЕНИЕ ИЗ WHITELIST")
    if not choice.isdigit():
        return
    index = int(choice) - 1
    if not 0 <= index < len(whitelist):
        return
    network = whitelist[index]
    info("Применяю конфигурацию whitelist...")
    if app.plugin_command(
        state,
        "fail2ban",
        "remove_whitelist",
        network=network,
    ):
        success(f"Удален из whitelist и применен: {network}")
    else:
        warn(
            f"Удален из whitelist: {network}, "
            "но Fail2ban не смог применить конфигурацию автоматически",
        )
    prompt("Нажмите Enter для продолжения")


def manage(
    state: AppState,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        whitelist = get_protocol(
            state,
            "fail2ban",
        ).config.setdefault("whitelist", [])
        effective_whitelist = facade._effective_whitelist(state)
        lines = [
            f"  {CYAN}{index:>2}.{NC} {network} {DIM}(ручной){NC}"
            for index, network in enumerate(whitelist, 1)
        ]
        lines.extend(
            f"      {network} {DIM}"
            f"(автоматический / из ignoreip){NC}"
            for network in effective_whitelist
            if network not in whitelist
        )
        panel(
            "Фактический Fail2ban ignoreip",
            lines if lines else ["  Список пуст"],
        )
        choice = menu([
            (
                "1",
                "➕ Добавить IP/подсеть",
                "Внести адрес в список исключений",
            ),
            (
                "2",
                "➖ Удалить IP/подсеть",
                "Исключить адрес из списка исключений",
            ),
            ("0", "↩ Назад", ""),
        ], "WHITELIST FAIL2BAN")
        if choice == "0":
            return
        if choice == "1":
            _add(state, app, whitelist)
        elif choice == "2":
            _remove(state, app, whitelist)


__all__ = ["manage"]
