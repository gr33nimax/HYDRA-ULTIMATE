"""Managed-node and cascade screens over the ApplicationService port."""

from __future__ import annotations

import secrets
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping

from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.contracts.managed_node_observations import DiagnosticReport, NodeView
from hydra.services.application import ApplicationService
from hydra.ui._menus.nodes_setup import install_node
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import ask, ask_secret, clear, confirm, error, kv, menu, panel, prompt, success


_SUB_LABELS = {
    "sync": "SUB : ✅SYNC",
    "wait": "SUB : ⏳WAIT",
    "error": "SUB : ❌ERROR",
    "unknown": "SUB : —",
}
_STATE_LABELS = {
    "ok": "Готово", "succeeded": "Завершено", "failed": "Ошибка",
    "pending": "Ожидает завершения", "running": "Выполняется",
    "recovery_required": "Требуется восстановление", "unknown": "Нет данных",
}


def render_node_card(
    view: NodeView,
    *,
    now: datetime | None = None,
    display_names: Mapping[str, str] | None = None,
) -> str:
    view.validate()
    checked = view.management_check
    current = now or datetime.now(timezone.utc)
    timestamp = _time_label(checked.checked_at if checked else None, current)
    health = _management_label(checked, current)
    applied = "—" if view.users_applied is None else str(view.users_applied)
    total = "—" if view.users_total is None else str(view.users_total)
    lines = [
        f"{view.definition.name} · {timestamp}",
        f"Управление: {health}",
        f"Пользователи {applied}/{total}",
        _SUB_LABELS[view.sub_state],
    ]
    for assignment in view.definition.protocols:
        name = assignment.name
        label = protocol_label(name, (display_names or {}).get(name, ""))
        check = view.protocol_checks.get(name)
        if check is None:
            lines.append(f"{label}: —")
        else:
            state = "✅" if check.outcome == "ok" else "❌" if check.outcome == "error" else "—"
            detail = " (конфигурация)" if check.kind == "configuration" else ""
            lines.append(f"{label}: {state}{detail}")
            if check.outcome == "error" and check.reason:
                lines.append(f"ошибка: {check.reason}")
    if view.operation and view.operation.state != "succeeded":
        lines.append(f"Операция: {view.operation.id} · {_STATE_LABELS.get(view.operation.state, view.operation.state)}")
        if view.operation.error:
            lines.append(f"Причина: {view.operation.error.get('reason', '')}")
    return "\n".join(lines)


def _time_label(value: str | None, now: datetime) -> str:
    if not value:
        return "—"
    try:
        checked = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        checked = checked.astimezone(now.tzinfo or timezone.utc)
        return checked.strftime("%H:%M")
    except (TypeError, ValueError):
        return "—"


def _management_label(check, now: datetime) -> str:
    if check is None or not check.checked_at:
        return "⚪ нет данных"
    try:
        checked = datetime.fromisoformat(check.checked_at.replace("Z", "+00:00"))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        age = (now - checked.astimezone(now.tzinfo or timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return "⚪ нет данных"
    if age < 0 or age > 600:
        return "⚪ нет данных"
    return "🟢 Online" if check.outcome == "ok" else "🔴 Offline" if check.outcome == "error" else "⚪ нет данных"


def menu_nodes(state, app: ApplicationService) -> None:
    del state
    while True:
        try:
            views = app.nodes.list()
            cascades = app.nodes.list_cascades()
        except Exception as exc:
            error(f"Список управляемых нод недоступен: {_reason(exc)}")
            return
        options: list[tuple[str, str, Any]] = [
            ("1", "Добавить ноду", "проверка SSH, план, подтверждение"),
            ("2", "Каскады", f"Маршрутов: {len(cascades)}"),
        ]
        indexed = {str(index + 3): view for index, view in enumerate(views)}
        options.extend((key, view.definition.name, _summary(view)) for key, view in indexed.items())
        options.append(("0", "Назад", ""))
        clear()
        choice = menu(options, "УПРАВЛЯЕМЫЕ НОДЫ")
        if choice == "0":
            return
        if choice == "1":
            try:
                install_node(app.admin.load_state(), app)
            except Exception as exc:
                error(f"Установка не завершена: {_reason(exc)}")
            prompt("Enter — продолжить")
        elif choice == "2":
            menu_cascades(app)
        elif choice in indexed:
            _node_card(indexed[choice], app)


def _node_card(view: NodeView, app: ApplicationService) -> None:
    while True:
        current = next((item for item in app.nodes.list() if item.definition.id == view.definition.id), None)
        if current is None:
            return
        view = current
        clear()
        panel("НОДА", render_node_card(view).splitlines(), wrap=True)
        options = [
            ("1", "Протоколы", "настройки, названия конфигураций и удаление"),
            ("2", "Синхронизировать", "обновить пользователей и настройки этой ноды"),
            ("3", "Диагностика", "проверить связь, протоколы и подписки"),
            ("4", "Удалить ноду", "удалить HYDRA с сервера и убрать ноду из подписок"),
        ]
        if _can_resume_install(view):
            options.append(("5", "Продолжить установку", "проверить незавершённый этап и применить конфигурацию"))
        options.append(("0", "Назад", ""))
        choice = menu(options, "КАРТОЧКА НОДЫ")
        if choice == "0":
            return
        try:
            if choice == "1":
                _protocols(view, app)
            elif choice == "2":
                report = app.nodes.sync(view.definition.id)
                _show_report("СИНХРОНИЗАЦИЯ", report)
            elif choice == "3":
                report = app.nodes.check(view.definition.id, deep=True)
                _show_report("ДИАГНОСТИКА", report)
            elif choice == "4":
                if _remove_node(view, app):
                    return
            elif choice == "5" and _can_resume_install(view):
                _resume_install(view, app)
        except Exception as exc:
            error(f"Операция не завершена: {_reason(exc)}")
        prompt("Enter — продолжить")


def _can_resume_install(view: NodeView) -> bool:
    operation = view.operation
    return bool(operation and operation.kind == "install" and operation.state != "succeeded"
                and not (operation.error and operation.error.get("stage") == "removal"))


def _resume_install(view: NodeView, app: ApplicationService) -> None:
    from contextlib import nullcontext
    from hydra.services.managed_nodes.credentials import SshPasswordChannel

    if not _can_resume_install(view) or view.operation is None:
        return
    if not confirm(f"Продолжить установку {view.definition.name}?", default=False):
        return
    password = ask_secret("Пароль SSH (пусто — SSH-ключ)")
    if password is None:
        return
    with SshPasswordChannel(password) if password else nullcontext(None) as auth:
        result = app.nodes.resume(view.operation.id, auth)
    _show_report("ПРОДОЛЖЕНИЕ УСТАНОВКИ", result)


def _protocols(view: NodeView, app: ApplicationService) -> None:
    from hydra.ui._menus.node_protocols import manage_node_protocols
    manage_node_protocols(view, app, _show_report)


def _remove_node(view: NodeView, app: ApplicationService) -> bool:
    cascades = [
        cascade for cascade in app.nodes.list_cascades() if view.definition.id in {cascade.entry_id, cascade.exit_id}
    ]
    if cascades:
        panel("СНАЧАЛА УДАЛИТЕ КАСКАДЫ", [f"{item.name}: {item.entry_id} → {item.exit_id}" for item in cascades])
        error("Нода используется в каскадах. Сначала удалите их, затем повторите удаление ноды.")
        return False
    if not confirm(
        f"Удалить HYDRA и ноду {view.definition.name}? Профили этой ноды исчезнут из подписок.",
        default=False,
    ):
        return False
    password = ask_secret("Пароль SSH для удаления HYDRA (пусто — SSH-ключ)")
    if password is None:
        return False
    from contextlib import nullcontext
    from hydra.services.managed_nodes.credentials import SshPasswordChannel

    auth_context = SshPasswordChannel(password) if password else nullcontext(None)
    with auth_context as auth:
        result = app.nodes.remove(view.definition.id, True, auth)
    _show_report("УДАЛЕНИЕ НОДЫ", result)
    return result.state == "succeeded"


def menu_cascades(app: ApplicationService) -> None:
    while True:
        try:
            cascades = app.nodes.list_cascades()
            nodes = app.nodes.list()
        except Exception as exc:
            error(f"Каскады недоступны: {_reason(exc)}")
            return
        indexed = {str(index + 1): item for index, item in enumerate(cascades)}
        options = [(key, item.name, f"{item.entry_id} → {item.exit_id}") for key, item in indexed.items()]
        options.extend([("A", "Добавить каскад", "маршрут через два сервера"), ("0", "Назад", "")])
        choice = menu(options, "КАСКАДЫ")
        if choice == "0":
            return
        if choice == "A":
            _create_cascade(app, nodes)
        elif choice in indexed:
            _cascade_card(indexed[choice], app)


def _create_cascade(app: ApplicationService, nodes: list[NodeView]) -> None:
    participants = [("base", "Основа"), *((item.definition.id, item.definition.name) for item in nodes)]
    entry = _choose_participant("ВХОД", participants)
    if entry is None:
        return
    exit = _choose_participant("ВЫХОД", participants)
    if exit is None:
        return
    options = app.nodes.cascade_options(entry, exit)
    supported = [item for item in options if item.supported]
    if not supported:
        error("Нет транспорта с подтверждённой совместимостью клиента, сервера и сквозной проверки на обоих узлах")
        for item in options:
            error(f"{protocol_label(item.name)}: {item.reason or 'не поддержан'}")
        return
    name = ask("Название профиля каскада")
    if not name or not name.strip():
        return
    selected: list[str] = []
    while True:
        options_menu = [
            (str(index), protocol_label(item.name), "выбран" if item.name in selected else "")
            for index, item in enumerate(supported, 1)
        ]
        done = str(len(options_menu) + 1)
        options_menu.extend([(done, "Готово", ""), ("0", "Отмена", "")])
        pick = menu(options_menu, "ПРОТОКОЛЫ КАСКАДА")
        if pick == "0":
            return
        if pick == done:
            break
        if pick.isdecimal() and 1 <= int(pick) <= len(supported):
            value = supported[int(pick) - 1].name
            selected.remove(value) if value in selected else selected.append(value)
    if not selected:
        error("Каскад требует хотя бы один протокол")
        return
    definition = CascadeDefinition(secrets.token_hex(12), name.strip(), entry, exit, selected)
    if not confirm(f"Создать {definition.name}: {entry} → {exit}?", default=False):
        return
    _show_report("СОЗДАНИЕ КАСКАДА", app.nodes.save_cascade(definition, confirmed=True))


def _cascade_card(definition: CascadeDefinition, app: ApplicationService) -> None:
    choice = menu(
        [
            ("1", "Переименовать", "ID и ключи не меняются"),
            ("2", "Удалить каскад", "убрать маршрут и его профили из подписок"),
            ("0", "Назад", ""),
        ],
        f"{definition.name} · {definition.entry_id} → {definition.exit_id}",
    )
    if choice == "1":
        name = ask("Новое имя каскада", definition.name)
        if name and name.strip() and name.strip() != definition.name:
            app.nodes.rename_cascade(definition.id, name.strip())
            success("Имя профиля изменено; маршрут и ключи сохранены")
    elif choice == "2" and confirm(f"Удалить каскад {definition.name}?", default=False):
        _show_report("УДАЛЕНИЕ КАСКАДА", app.nodes.remove_cascade(definition.id, confirmed=True))


def _choose_participant(header: str, participants: list[tuple[str, str]]) -> str | None:
    choice = menu(
        [
            (str(index), label, "основа" if node_id == "base" else node_id)
            for index, (node_id, label) in enumerate(participants, 1)
        ]
        + [("0", "Отмена", "")],
        header,
    )
    return participants[int(choice) - 1][0] if choice.isdecimal() and 1 <= int(choice) <= len(participants) else None


def _summary(view: NodeView) -> str:
    card = render_node_card(view).splitlines()
    return " · ".join(card[1:4])


def _show_report(title: str, report: Any) -> None:
    if isinstance(report, DiagnosticReport):
        from hydra.ui._menus.node_reports import diagnostic_lines

        panel(title, diagnostic_lines(report), wrap=True)
        return
    if hasattr(report, "state"):
        lines = [f"Операция: {report.id}", f"Состояние: {_STATE_LABELS.get(report.state, report.state)}"]
        if report.error:
            lines.append(f"{report.error.get('stage')}: {report.error.get('reason')}")
        panel(title, lines, wrap=True)
        return
    if hasattr(report, "nodes"):
        lines = []
        for node_id, value in report.nodes.items():
            status = value.get("status", value.get("outcome", "unknown"))
            lines.append(f"{node_id}: {_STATE_LABELS.get(status, status)}")
            if value.get("operation_id"):
                lines.append(f"Операция: {value['operation_id']}")
            if value.get("error"):
                lines.append(f"Причина: {value['error']}")
        shown_errors = {value.get("error") for value in report.nodes.values()}
        lines.extend(item for item in report.errors if item not in shown_errors)
        panel(title, lines or ["Нет новых данных"], wrap=True)
        return
    panel(title, [str(report)], wrap=True)


def _reason(exc: Exception) -> str:
    reason = str(exc) if str(exc) else type(exc).__name__
    return {
        "remove or reconfigure affected cascades before changing this node":
            "Нода используется в каскадах. Сначала удалите их, затем измените протоколы.",
        "managed-node target already has an active operation":
            "На ноде выполняется другая операция. Дождитесь её завершения или продолжите синхронизацию.",
    }.get(reason, reason)


__all__ = ["menu_nodes", "menu_cascades"]
