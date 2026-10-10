"""Readable managed-node diagnostics without dataclass representations."""
from __future__ import annotations

from hydra.contracts.managed_node_observations import CheckResult, DiagnosticReport
from hydra.ui.protocol_ui import protocol_label

_OUTCOMES = {
    "ok": "✅ OK",
    "error": "❌ Ошибка",
    "unknown": "— Нет данных",
    "not_applicable": "— Проверка не предусмотрена",
}
_REASONS = {
    "applied user identities or restrictions differ from the base": "Пользователи или их ограничения отличаются от основы",
    "no committed apply receipt": "Применение конфигурации ещё не подтверждено",
    "configured inbound is not confirmed": "Рабочая конфигурация протокола не подтверждена",
    "no compatible native client is declared": "Автоматическая проверка соединения для этого протокола не поддерживается",
    "current technical probe material is unavailable": "Нет данных для проверки соединения: сначала завершите синхронизацию",
    "no confirmed profile bundle matches the applied receipt": "Нет подтверждённых профилей для текущей конфигурации",
    "confirmed profiles do not cover current users and protocols": "Подтверждённые профили не соответствуют пользователям и протоколам",
}


def _check_lines(label: str, check: CheckResult) -> list[str]:
    lines = [f"{label}: {_OUTCOMES.get(check.outcome, check.outcome)}"]
    if check.reason:
        lines.append(f"  {_REASONS.get(check.reason, check.reason)}")
    return lines


def diagnostic_lines(report: DiagnosticReport) -> list[str]:
    lines = []
    for label, check in (
        ("Управление", report.management), ("Работа ядра", report.runtime),
        ("Пользователи", report.users), ("Подписка ноды", report.subscription),
    ):
        lines.extend(_check_lines(label, check))
    for name, checks in report.protocols.items():
        lines.append(protocol_label(name))
        for kind, check in checks.items():
            label = {"configuration": "Конфигурация", "connection": "Соединение"}.get(kind, kind)
            lines.extend(_check_lines(f"  {label}", check))
    return lines
