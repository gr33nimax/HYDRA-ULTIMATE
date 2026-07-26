"""System log navigation and compatibility helpers."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui import log_viewer
from hydra.ui._menus.monitoring_support import (
    _is_enter_pressed,
    _unit_active,
    _unit_known,
)
from hydra.ui.tui import (
    BOLD,
    GREEN,
    NC,
    _bytes_auto,
    clear,
    menu,
    prompt,
    title,
    warn,
)


_LOG_OPTIONS = [
    ("1", "📋 Sing-Box", "journal", "sing-box"),
    ("2", "🔄 Sync Agent", "file", "/var/log/hydra/sync-agent.log"),
    ("3", "📊 Clash API", "file", "/var/log/hydra/traffic-daemon.log"),
    ("4", "🔗 qWDTT", "journal", "wdtt"),
    ("5", "🌐 Caddy L4", "journal", "caddy-l4"),
    ("6", "📨 Telemt", "journal", "telemt"),
    ("7", "🔐 DNSCrypt", "journal", "dnscrypt-proxy"),
    ("8", "🔒 Fail2ban", "journal", "fail2ban"),
    ("9", "🌐 Naive access", "file", "/var/log/caddy-naive/access.log"),
    ("A", "🍯 Honeypot events", "file", "/var/log/hydra-honeypot.log"),
    ("B", "📦 Сервер подписок", "journal", "hydra-sub"),
    ("C", "🤖 Telegram Admin Bot", "journal", "hydra-tg-admin"),
    ("D", "🛠 HYDRA install", "file", "/var/log/hydra/install.log"),
]


def _menu_logs(state: AppState, app: ApplicationService):
    lines_count = 30
    while True:
        try:
            monitoring_from_application(app).maintain_traffic_log()
        except Exception:
            pass
        clear()
        title("📋 Просмотр системных логов")
        print()
        print(
            f"  {BOLD}Текущий лимит строк для просмотра:{NC} "
            f"{GREEN}{lines_count}{NC}\n",
        )
        options = [
            (
                key,
                name,
                (
                    source if source_type == "file"
                    else f"journalctl -u {source}"
                ) + f" · {_log_source_status(source_type, source, app)}",
            )
            for key, name, source_type, source in _LOG_OPTIONS
        ]
        options += [
            ("-", "", ""),
            ("L", f"📝 Изменить лимит строк ({lines_count})", ""),
            ("0", "↩ Назад", ""),
        ]
        choice = menu(options, "ВЫБОР ЛОГ-ФАЙЛА")
        if choice == "0":
            break
        if choice.upper() == "L":
            try:
                new_limit = int(prompt(
                    "Введите количество строк",
                    str(lines_count),
                ))
                if new_limit > 0:
                    lines_count = new_limit
            except ValueError:
                warn("Введите корректное число.")
                prompt("Нажмите Enter")
            continue
        selected = next(
            (option for option in _LOG_OPTIONS if choice == option[0]),
            None,
        )
        if selected:
            _, name, source_type, source = selected
            _show_log_source(
                name,
                source_type,
                source,
                lines_count,
                app,
            )


def _log_source_status(
    source_type: str,
    source: str,
    app: ApplicationService,
) -> str:
    if (
        source_type != "file"
        and not _unit_active(source, app)
        and not _unit_known(source, app)
    ):
        return "не установлено"
    return log_viewer.source_status(
        app.logs,
        source_type,
        source,
        bytes_auto=_bytes_auto,
    )


def _read_log_source(
    source_type: str,
    source: str,
    num_lines: int,
    app: ApplicationService,
) -> tuple[list[str], str]:
    return log_viewer.read_source(
        app.logs,
        source_type,
        source,
        num_lines,
    )


def _show_log_source(
    title_text: str,
    source_type: str,
    source: str,
    num_lines: int,
    app: ApplicationService,
):
    log_viewer.show_source(
        title_text,
        source_type,
        source,
        num_lines,
        logs=app.logs,
        enter_pressed=_is_enter_pressed,
        sleep=monitoring_from_application(app).sleep,
    )


def _show_log_file(
    title_text: str,
    path_str: str,
    num_lines: int,
    app: ApplicationService,
):
    """Обратная совместимость для внутренних меню с файловыми логами."""
    log_viewer.show_file(
        title_text,
        path_str,
        num_lines,
        logs=app.logs,
        enter_pressed=_is_enter_pressed,
        sleep=monitoring_from_application(app).sleep,
    )


def _watch_log_file(
    title_text: str,
    path_str: str,
    app: ApplicationService,
):
    log_viewer.watch_file(
        title_text,
        path_str,
        app.logs,
        _is_enter_pressed,
    )


def _watch_journal(
    title_text: str,
    unit: str,
    app: ApplicationService,
):
    log_viewer.watch_journal(
        title_text,
        unit,
        app.logs,
        _is_enter_pressed,
        sleep=monitoring_from_application(app).sleep,
    )


def _sync_agent_log_snapshot(
    log_path: object,
    app: ApplicationService,
    now_timestamp: float | None = None,
) -> tuple[str, str, bool]:
    return log_viewer.sync_snapshot(
        app.logs,
        str(log_path),
        now_timestamp,
    )
