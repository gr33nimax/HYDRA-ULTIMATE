"""Independent sections of the read-only HYDRA runtime report."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from hydra.services.application import ApplicationService


_SERVICES = (
    "sing-box",
    "caddy-l4",
    "dnscrypt-proxy",
    "fail2ban",
    "hydra-traffic-daemon",
)
_EVENT_NAMES = {
    "started": "применение начато",
    "fragments_collected": "конфигурация плагинов собрана",
    "nft_applied": "сетевые правила применены",
    "plugins_applied": "плагины применены",
    "committed": "применение успешно завершено",
    "rolled_back": "изменения отменены",
    "failed": "применение завершилось ошибкой",
    "rejected": "применение отклонено",
}


@dataclass
class DiagnosticReport:
    """Mutable report buffer with explicit error accounting."""

    checked_at: str
    width: int = 74
    lines: list[str] = field(default_factory=list)
    errors: int = 0

    def __post_init__(self) -> None:
        self.lines.extend(
            [
                "╭" + "─" * self.width + "╮",
                "│" + "HYDRA — диагностика".center(self.width) + "│",
                "│" + f"Проверка: {self.checked_at}".center(self.width) + "│",
                "╰" + "─" * self.width + "╯",
            ],
        )

    def section(self, name: str) -> None:
        self.lines.extend(
            ["", f"┌─ {name} " + "─" * max(1, self.width - len(name) - 4)],
        )

    def item(self, marker: str, text: str) -> None:
        self.lines.append(f"│ {marker:<7} {text}")

    def fail(self, text: str) -> None:
        self.errors += 1
        self.item("[ERROR]", text)

    def render(self) -> str:
        result = "ERROR" if self.errors else "OK"
        conclusion = (
            "ОБНАРУЖЕНЫ ОШИБКИ" if self.errors else "СИСТЕМА В НОРМЕ"
        )
        self.lines.extend(["", f"└─ ИТОГ: {conclusion} [{result}]"])
        return "\n".join(self.lines)


def append_state(report: DiagnosticReport, app: ApplicationService) -> None:
    report.section("СОСТОЯНИЕ HYDRA")
    try:
        state = app.admin.load_state()
        enabled = [
            name
            for name, value in state.protocols.items()
            if value.enabled
        ]
        report.item(
            "[OK]",
            f"state.json       корректен, schema {state.version}",
        )
        report.item("[OK]", f"Пользователи      {len(state.users)}")
        report.item(
            "[OK]",
            f"Протоколы         {', '.join(enabled) if enabled else 'нет'}",
        )
    except Exception as exc:
        report.fail(f"state.json        {exc}")


def append_singbox(report: DiagnosticReport, app: ApplicationService) -> None:
    report.section("ЯДРО SING-BOX")
    try:
        singbox = app.admin.singbox_diagnostics()
        if singbox.installed:
            version = singbox.version or "версия не определена"
            report.item("[OK]", f"Sing-Box          установлен, {version}")
        else:
            report.fail("Sing-Box          не установлен")
        if singbox.config_exists:
            report.item("[OK]", "Конфигурация      существует")
        else:
            report.item("[WARNING]", "Конфигурация      ещё не создана")
        if singbox.config_check_ok is True:
            report.item("[OK]", "Проверка конфига  синтаксис корректен")
        elif singbox.config_check_ok is False:
            report.fail(
                f"Проверка конфига  {singbox.config_check_detail[:300]}",
            )
        elif singbox.config_check_detail:
            report.item(
                "[WARNING]",
                "Проверка конфига  недоступна: "
                f"{singbox.config_check_detail}",
            )
    except Exception as exc:
        report.fail(f"Sing-Box          проверка недоступна: {exc}")
    report.item("[INFO]", f"Ошибка применения  {app.apply_error() or 'нет'}")


def append_services(
    report: DiagnosticReport,
    app: ApplicationService,
    *,
    windows: bool,
) -> None:
    report.section("СЕРВИСЫ")
    if windows:
        report.item("[INFO]", "systemd            недоступен в Windows-окружении")
        return
    shown = 0
    for service in _SERVICES:
        try:
            status = app.admin.unit_diagnostics(service)
            if not status.loaded:
                continue
            shown += 1
            active = status.active or "не установлен"
            enabled = status.enabled or "не включён"
            marker = "OK" if status.active_ok else "WARNING"
            if not status.active_ok and status.enabled_ok:
                report.errors += 1
            report.item(
                f"[{marker}]",
                f"{service:<20} {active}, автозапуск: {enabled}",
            )
        except Exception as exc:
            report.item(
                "[WARNING]",
                f"{service:<20} проверка недоступна: {exc}",
            )
    if not shown:
        report.item(
            "[INFO]",
            "Сервисы            управляемые systemd-сервисы не установлены",
        )


def _partition_plugins(
    statuses: dict,
) -> tuple[list[tuple[str, dict]], list[tuple[str, dict]]]:
    active: list[tuple[str, dict]] = []
    disabled: list[tuple[str, dict]] = []
    for name, status in statuses.items():
        if not status.get("installed"):
            continue
        (active if status.get("enabled") else disabled).append((name, status))
    return active, disabled


def append_plugins(
    report: DiagnosticReport,
    app: ApplicationService,
    *,
    windows: bool,
) -> None:
    report.section("ПЛАГИНЫ")
    if windows:
        report.item("[INFO]", "Runtime-статусы    доступны только на Linux")
        return
    try:
        active, disabled = _partition_plugins(app.protocols.statuses())
        if active:
            report.lines.append("│ АКТИВНЫЕ")
            for name, status in active:
                running = bool(status.get("running"))
                if not running:
                    report.errors += 1
                marker = "[OK]" if running else "[ERROR]"
                port = str(status.get("port") or "—")
                state = "запущен" if running else "не запущен"
                report.item(
                    marker,
                    f"{name:<18} {state:<11} порт: {port}",
                )
        if disabled:
            report.lines.append(
                "│ ОТКЛЮЧЕНЫ (установлены, но не участвуют в работе)",
            )
            for name, status in disabled:
                suffix = (
                    f", порт: {status.get('port')}"
                    if status.get("port")
                    else ""
                )
                report.item("[INFO]", f"{name:<18} отключён{suffix}")
        if not active and not disabled:
            report.item("[INFO]", "Установленные     плагины отсутствуют")
    except Exception as exc:
        report.fail(f"Статусы плагинов   не удалось получить: {exc}")


def _append_latest_event(
    report: DiagnosticReport,
    latest: dict[str, object],
) -> None:
    event = str(latest.get("event", "unknown"))
    marker = "OK" if event == "committed" else "WARNING"
    if event in {"rolled_back", "failed", "rejected"}:
        report.errors += 1
    report.item(
        f"[{marker}]",
        f"Результат          {_EVENT_NAMES.get(event, event)}",
    )
    if latest.get("ts"):
        report.item("[INFO]", f"Время              {latest['ts']}")
    if latest.get("stage"):
        report.item("[INFO]", f"Этап               {latest['stage']}")
    if latest.get("error"):
        report.item(
            "[ERROR]",
            f"Причина            {str(latest['error'])[:500]}",
        )


def append_journal(report: DiagnosticReport, app: ApplicationService) -> None:
    report.section("ПОСЛЕДНЕЕ ПРИМЕНЕНИЕ")
    try:
        entries = [
            line.strip()
            for line in app.admin.read_text_lines(app.journal_path())
            if line.strip()
        ]
        report.item("[OK]", f"Журнал             {len(entries)} событий")
        if entries:
            _append_latest_event(report, json.loads(entries[-1]))
    except FileNotFoundError:
        report.item(
            "[INFO]",
            "Журнал             применений ещё не зарегистрировано",
        )
    except (OSError, ValueError, TypeError) as exc:
        report.item("[WARNING]", f"Журнал             недоступен: {exc}")


def build_report(
    app: ApplicationService,
    *,
    checked_at: str,
    windows: bool,
) -> str:
    """Compose all independent report sections into the stable text format."""
    report = DiagnosticReport(checked_at)
    append_state(report, app)
    append_singbox(report, app)
    append_services(report, app, windows=windows)
    append_plugins(report, app, windows=windows)
    append_journal(report, app)
    return report.render()


__all__ = ["DiagnosticReport", "build_report"]
