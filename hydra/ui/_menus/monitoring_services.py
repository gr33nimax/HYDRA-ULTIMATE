"""Sync Agent and Clash API settings controllers."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui._menus.monitoring_logs import (
    _show_log_file,
    _sync_agent_log_snapshot,
)
from hydra.ui._menus.monitoring_support import (
    _application,
    _apply_error_text,
    _unit_active,
)
from hydra.ui.tui import (
    DIM,
    GREEN,
    NC,
    RED,
    _bytes_auto,
    clear,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    warn,
)


def _menu_sync_agent(state: AppState, app: ApplicationService):
    while True:
        state = app.admin.load_state()
        clear()
        timer_active = _unit_active("hydra-sync-agent.timer", app)
        log_path = monitoring_from_application(app).sync_agent_log_path()
        last_log_line, log_freshness, log_stale = (
            _sync_agent_log_snapshot(log_path, app)
        )
        log_info = app.logs.source_info("file", str(log_path))
        freshness_color = RED if timer_active and log_stale else DIM
        lines = [
            kv("Таймер (5 мин):", f"{GREEN}активен 🟢{NC}" if timer_active else f"{RED}отключен 🔴{NC}"),
            kv(
                "Лог-файл:",
                (
                    _bytes_auto(log_info.size_bytes)
                    if log_info.size_bytes is not None
                    else "не создан"
                ),
            ),
            kv("Последняя запись:", f"{DIM}{last_log_line}{NC}"),
            kv("Актуальность:", f"{freshness_color}{log_freshness}{NC}"),
        ]
        panel("Управление Sync Agent", lines)

        maintenance_choices: dict[str, tuple[str, bool]] = {}
        maintenance_items: list[tuple[str, str, str]] = []
        for index, job in enumerate(app.protocols.maintenance_jobs(), start=4):
            enabled = bool(state.install.get(job.enabled_flag, True))
            key = str(index)
            maintenance_choices[key] = (job.enabled_flag, enabled)
            color = GREEN if enabled else RED
            marker = "ВКЛ" if enabled else "ВЫКЛ"
            maintenance_items.append(
                (
                    key,
                    f"{job.title}: {color}[{marker}]{NC}",
                    job.description,
                ),
            )
        limits_auto = state.install.get("sync_limits_enabled", True)
        updates_auto = state.install.get("sync_updates_enabled", True)
        limits_key = str(4 + len(maintenance_items))
        updates_key = str(5 + len(maintenance_items))
        toggle_label = "⏹ Отключить Sync Agent" if timer_active else "▶ Включить Sync Agent"
        toggle_desc = "Остановить периодическую синхронизацию" if timer_active else "Проверять лимиты и сроки каждые 5 минут"
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("2", "⚡ Запустить сейчас", "Проверить лимиты, задачи плагинов и обновление Sing-Box"),
            ("3", "📋 Показать лог", "Последние 30 строк sync-agent.log"),
            ("-", "", ""),
            *maintenance_items,
            (limits_key, f"👥 Автопроверка лимитов: {GREEN}[ВКЛ]{NC}" if limits_auto else f"👥 Автопроверка лимитов: {RED}[ВЫКЛ]{NC}",
             "Блокировать пользователей при превышении трафика/TTL"),
            (updates_key, f"🆙 Автопроверка обновлений ядра: {GREEN}[ВКЛ]{NC}" if updates_auto else f"🆙 Автопроверка обновлений ядра: {RED}[ВЫКЛ]{NC}",
             "Раз в 24 часа проверять наличие обновлений Sing-Box"),
            ("0", "↩ Назад", ""),
        ], "SYNC AGENT")

        if choice == "0":
            break
        if choice == "1":
            _toggle_sync_agent(timer_active, app)
        elif choice == "2":
            _run_sync_agent(app)
        elif choice == "3":
            _show_log_file("Sync Agent", str(log_path), 30, app)
        elif choice in maintenance_choices:
            flag, enabled = maintenance_choices[choice]
            state = app.admin.set_install_flag(
                flag,
                not enabled,
            )
        elif choice == limits_key:
            state = app.admin.set_install_flag(
                "sync_limits_enabled",
                not limits_auto,
            )
        elif choice == updates_key:
            state = app.admin.set_install_flag(
                "sync_updates_enabled",
                not updates_auto,
            )


def _toggle_sync_agent(
    timer_active: bool,
    app: ApplicationService,
) -> None:
    if timer_active:
        info("Отключение Sync Agent...")
        if app.admin.configure_sync_agent(False):
            success("Sync Agent отключён")
        else:
            error("Не удалось отключить Sync Agent")
    else:
        if app.admin.configure_sync_agent(True):
            success("Sync Agent включён (каждые 5 минут)")
        else:
            error("Не удалось включить Sync Agent")
    prompt("Нажмите Enter")


def _run_sync_agent(app: ApplicationService) -> None:
    info("Запуск ручной синхронизации...")
    try:
        ok, message = app.admin.run_sync_agent()
        if ok:
            success("Синхронизация успешно выполнена")
        else:
            warn(f"Синхронизация завершена с ошибками: {message}")
    except Exception as exc:
        error(f"Ошибка при синхронизации: {exc}")
    prompt("Нажмите Enter")


def _menu_clash_api(
    state: AppState,
    app: ApplicationService | None = None,
):
    app = _application(app)
    while True:
        state = app.admin.load_state()
        clear()
        enabled_status = getattr(state.network, "clash_api_enabled", False)
        daemon_active = _unit_active("hydra-traffic-daemon.service", app)
        lines = [
            kv("Clash API:", f"{GREEN}активно 🟢{NC}" if enabled_status and daemon_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Демон статистики:", f"{GREEN}активно 🟢{NC}" if daemon_active else f"{DIM}неактивно ⚪{NC}"),
        ]
        panel("Clash API", lines)
        toggle_label = "⏹ Отключить Clash API" if enabled_status else "▶ Включить Clash API"
        toggle_desc = "Отключить Clash API и демон статистики" if enabled_status else "Включить локальный Clash API и демон статистики"
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("0", "↩ Назад", ""),
        ], "CLASH API")
        if choice == "0":
            break
        if choice == "1":
            desired = not enabled_status
            state = app.admin.set_clash_api(desired)
            info("Пересборка конфигурации Sing-Box...")
            if app.apply(state):
                success(
                    "Clash API включён"
                    if desired else "Clash API отключён",
                )
            else:
                state = app.admin.set_clash_api(enabled_status)
                app.apply(state)
                error(_apply_error_text(
                    "Не удалось применить настройку; прежнее состояние восстановлено",
                    app,
                ))
            prompt("Нажмите Enter")
