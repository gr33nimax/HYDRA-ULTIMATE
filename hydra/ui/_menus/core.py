"""Core and Sing-Box menu controller."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui._menus.kernel import handle_kernel_choice
from hydra.ui.tui import (
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    _ok,
    clear,
    confirm,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    warn,
)


@dataclass(frozen=True)
class CoreMenuDependencies:
    clear: Callable[[], None]
    panel: Callable[..., None]
    kv: Callable[[str, str], str]
    status_marker: Callable[[bool], str]
    menu: Callable[..., str]
    info: Callable[[str], None]
    success: Callable[[str], None]
    warn: Callable[[str], None]
    prompt: Callable[[str], str]
    error: Callable[[str], None]
    apply_error_text: Callable[[str, ApplicationService], str]
    apply_network_tuning: Callable[[ApplicationService], None]
    rollback_network_tuning: Callable[[ApplicationService], None]
    yellow: str
    dim: str
    reset: str


def run_core_menu(
    state: AppState,
    app: ApplicationService,
    deps: CoreMenuDependencies,
) -> None:
    while True:
        state = app.admin.load_state()
        deps.clear()
        kernel_status = app.kernel.status(state)
        installed = kernel_status.runtime.installed
        running = kernel_status.runtime.running
        version = kernel_status.runtime.version

        update_available = state.install.get(
            "singbox_update_available",
            False,
        )
        latest_version = state.install.get("singbox_latest_version", "")

        version_text = version or "—"
        if installed and update_available:
            version_text += f" {deps.yellow}(Доступно обновление){deps.reset}"

        deps.panel(
            "Sing-Box",
            [
                deps.kv(
                    "Статус:",
                    f"{deps.status_marker(running)} "
                    f"{'запущен' if running else 'остановлен'}",
                ),
                deps.kv("Версия:", version_text),
                deps.kv("Провайдер:", kernel_status.runtime.provider),
                deps.kv("Канал:", state.kernel.channel),
                deps.kv(
                    "Конфиг:",
                    f"{deps.dim}/etc/sing-box/config.json{deps.reset}",
                ),
                deps.kv(
                    "Лог:",
                    f"{deps.dim}journalctl -u sing-box{deps.reset}",
                ),
            ],
        )

        items = [
            (
                "1",
                "📦 Установить выбранное ядро"
                if not installed
                else "🔄 Переустановить",
                state.kernel.provider,
            ),
            (
                "2",
                "▶️  Запустить" if not running else "⏸️  Остановить",
                "",
            ),
            (
                "3",
                "🔄 Применить конфиг",
                "Собрать /etc/sing-box/config.json и перезагрузить",
            ),
            (
                "4",
                "🚀 Оптимизировать сеть",
                "BBR/FQ, TCP/UDP-буферы и очереди в один клик",
            ),
            (
                "5",
                "↩️  Откатить оптимизацию сети",
                "Восстановить параметры до первого применения",
            ),
        ]

        other_provider = (
            "hydracore"
            if state.kernel.provider == "sing-box-extended"
            else "sing-box-extended"
        )
        items.append((
            "7",
            f"⇄ Переключить ядро на {other_provider}",
            "Проверка digest, config-check, health и автоматический rollback",
        ))

        if installed:
            if update_available:
                items.append(
                    (
                        "6",
                        "🆙 Установить обновление",
                        "Доступна версия "
                        f"{state.kernel.provider} {latest_version}",
                    ),
                )
            else:
                items.append(
                    (
                        "X",
                        "🆙 Установить обновления",
                        f"Установлена последняя версия {state.kernel.provider}",
                    ),
                )
        items.append(("0", "↩ Назад", ""))

        choice = deps.menu(items, "ЯДРО И СИСТЕМА")
        if choice == "0":
            return
        _handle_core_choice(
            choice,
            state,
            app,
            deps,
            installed=installed,
            running=running,
            update_available=update_available,
        )


def _handle_core_choice(
    choice: str,
    state: AppState,
    app: ApplicationService,
    deps: CoreMenuDependencies,
    *,
    installed: bool,
    running: bool,
    update_available: bool,
) -> None:
    if handle_kernel_choice(
        choice,
        state,
        app,
        deps,
        installed=installed,
        update_available=update_available,
        confirm_action=confirm,
    ):
        return
    if choice == "2":
        if running:
            app.admin.stop_singbox()
            deps.success("Остановлен")
        elif app.admin.start_singbox():
            deps.success("Запущен")
        else:
            deps.error(
                "Не удалось запустить. "
                "Проверьте: systemctl status sing-box",
            )
        deps.prompt("Нажмите Enter")
    elif choice == "3":
        deps.info("Пересобираю конфиг...")
        if app.apply(state):
            deps.success("Конфиг применён, Sing-Box перезагружен")
        else:
            deps.error(
                deps.apply_error_text(
                    "Ошибка применения конфигурации",
                    app,
                ),
            )
        deps.prompt("Нажмите Enter")
    elif choice == "4":
        deps.apply_network_tuning(app)
    elif choice == "5":
        deps.rollback_network_tuning(app)


def _apply_error_text(
    default: str = "Ошибка применения конфигурации",
    app: ApplicationService | None = None,
) -> str:
    if app is None:
        raise ValueError("ApplicationService must be injected")
    return app.apply_error() or default


def _apply_network_tuning_menu(app: ApplicationService) -> None:
    if not confirm(
        "Применить оптимальный сетевой профиль HYDRA? "
        "Текущие значения будут сохранены",
        default=True,
    ):
        return
    info("Настраиваю сетевой стек VPS...")
    try:
        report = app.admin.apply_network_tuning()
    except Exception as exc:
        error(f"Не удалось применить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    changed = sum(
        1 for item in report["sysctl"].values() if item.get("changed")
    )
    skipped = sum(
        1 for item in report["sysctl"].values() if item.get("skipped")
    )
    lines = [
        f"  Изменено параметров: {GREEN}{changed}{NC}",
        f"  BBR: {_ok(report['bbr_available'])}",
        f"  Постоянный профиль: {DIM}{report['config_path']}{NC}",
    ]
    if skipped:
        lines.append(f"  Не поддерживается ядром: {YELLOW}{skipped}{NC}")
    lines.extend(f"  {RED}{message}{NC}" for message in report["errors"][:5])
    panel("Сетевая оптимизация", lines)
    if report["success"]:
        success("Сетевой профиль применён. Перезагрузка не требуется")
    else:
        warn("Профиль применён частично; подробности показаны выше")
    prompt("Нажмите Enter")


def _rollback_network_tuning_menu(app: ApplicationService) -> None:
    if not confirm(
        "Восстановить сетевые параметры до оптимизации?",
        default=False,
    ):
        return
    try:
        report = app.admin.rollback_network_tuning()
    except Exception as exc:
        error(f"Не удалось откатить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    if report["success"]:
        success(f"Восстановлено параметров: {report['restored']}")
    else:
        error("Не удалось полностью откатить сетевой профиль")
        for message in report["errors"]:
            warn(message)
    prompt("Нажмите Enter")


def menu_core(state: AppState, app: ApplicationService) -> None:
    run_core_menu(
        state,
        app,
        CoreMenuDependencies(
            clear=clear,
            panel=panel,
            kv=kv,
            status_marker=_ok,
            menu=menu,
            info=info,
            success=success,
            warn=warn,
            prompt=prompt,
            error=error,
            apply_error_text=_apply_error_text,
            apply_network_tuning=_apply_network_tuning_menu,
            rollback_network_tuning=_rollback_network_tuning_menu,
            yellow=YELLOW,
            dim=DIM,
            reset=NC,
        ),
    )


__all__ = [
    "CoreMenuDependencies",
    "_apply_network_tuning_menu",
    "_rollback_network_tuning_menu",
    "menu_core",
    "run_core_menu",
]
