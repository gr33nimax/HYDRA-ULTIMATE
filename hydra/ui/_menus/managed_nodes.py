"""Managed-node and cascade screens over the ApplicationService port."""

from __future__ import annotations

import secrets
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping

from hydra.contracts.managed_node_models import CascadeDefinition, ProtocolAssignment
from hydra.contracts.managed_node_observations import NodeView
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
            lines.append(f"{label}: {state}")
            if check.outcome == "error" and check.reason:
                lines.append(f"ошибка: {check.reason}")
    return "\\n".join(lines)


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
            ("2", "Каскады", f"{len(cascades)} маршрутов, только две разные стороны"),
        ]
        indexed = {str(index + 3): view for index, view in enumerate(views)}
        options.extend((key, view.definition.name, _summary(view)) for key, view in indexed.items())
        options.append(("0", "Назад", ""))
        clear()
        choice = menu(options, "УПРАВЛЯЕМЫЕ НОДЫ")
        if choice == "0":
            return
        if choice == "1":
            install_node(app.admin.load_state(), app)
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
        choice = menu(
            [("1", "Протоколы", "изменить публичные параметры и применить"),
             ("2", "Синхронизировать", "только выбранная нода"),
             ("3", "Диагностика", "management, runtime, SUB и реальные проверки"),
             ("4", "Удалить ноду", "только после штатного удаления на VPS"),
             ("0", "Назад", "")],
            "КАРТОЧКА НОДЫ",
        )
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
        except Exception as exc:
            error(f"Операция не завершена: {_reason(exc)}")
        prompt("Enter — продолжить")


def _protocols(view: NodeView, app: ApplicationService) -> None:
    current = {item.name: item for item in view.definition.protocols}
    while True:
        options = [
            (str(index), protocol_label(name), "настроен")
            for index, name in enumerate(sorted(current), 1)
        ]
        add_key = str(len(options) + 1)
        options.extend([(add_key, "Добавить транспорт", "только реализованные формы"), ("0", "Назад", "")])
        selected_key = menu(options, "ПРОТОКОЛЫ НОДЫ")
        if selected_key == "0":
            return
        names = sorted(current)
        if selected_key == add_key:
            from hydra.plugins.base import PluginCategory
            from hydra.ui._menus.node_protocol_fields import PROTOCOL_FIELDS

            available = [
                item for item in app.protocols.list(PluginCategory.TRANSPORT)
                if item.meta.name in PROTOCOL_FIELDS and item.meta.name not in current
                and (item.meta.capabilities.subscription_enabled or item.meta.capabilities.hydra_v2_subscription_enabled)
            ]
            pick = menu(
                [(str(index), protocol_label(item.meta.name, getattr(item.meta, "display_name", "")), "")
                 for index, item in enumerate(available, 1)] + [("0", "Назад", "")],
                "ДОБАВИТЬ ПРОТОКОЛ",
            )
            if not pick.isdecimal() or not 1 <= int(pick) <= len(available):
                continue
            protocol = available[int(pick) - 1].meta.name
            before = ProtocolAssignment(protocol, {})
        else:
            if not selected_key.isdecimal() or not 1 <= int(selected_key) <= len(names):
                continue
            protocol = names[int(selected_key) - 1]
            before = current[protocol]
        from hydra.ui._menus.node_protocol_fields import collect_protocol_config

        parameters = collect_protocol_config(protocol, dict(before.parameters))
        if parameters is None:
            continue
        if not any(key == "port" or key.endswith("_port") for key in parameters):
            parameters["port"] = 443
        assignment = ProtocolAssignment(protocol, parameters)
        if not confirm(f"Применить {protocol_label(protocol)} на {view.definition.name}?", default=False):
            continue
        app.nodes.configure_protocol(view.definition.id, assignment, confirmed=True)
        return


def _remove_node(view: NodeView, app: ApplicationService) -> bool:
    cascades = [
        cascade for cascade in app.nodes.list_cascades()
        if view.definition.id in {cascade.entry_id, cascade.exit_id}
    ]
    if cascades:
        panel("СНАЧАЛА УДАЛИ КАСКАДЫ", [f"{item.name}: {item.entry_id} → {item.exit_id}" for item in cascades])
        error("Ноду нельзя забыть или отсоединить; очисти каскады и подтверждённо удали VPS")
        return False
    if not confirm(
        f"Удалить HYDRA и ноду {view.definition.name}? Профили этой ноды исчезнут из подписок.",
        default=False,
    ):
        return False
    password = ask_secret("Пароль SSH для штатного uninstall (пусто — SSH-ключ)")
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
        options.extend([("A", "Добавить каскад", "только доказанные одноимённые транспорты"), ("0", "Назад", "")])
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
        [("1", "Переименовать", "ID и ключи не меняются"),
         ("2", "Удалить каскад", "только его контексты и профили"), ("0", "Назад", "")],
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
        [(str(index), label, "основа" if node_id == "base" else node_id)
         for index, (node_id, label) in enumerate(participants, 1)] + [("0", "Отмена", "")],
        header,
    )
    return participants[int(choice) - 1][0] if choice.isdecimal() and 1 <= int(choice) <= len(participants) else None


def _summary(view: NodeView) -> str:
    card = render_node_card(view).splitlines()
    return " · ".join(card[1:4])


def _show_report(title: str, report: Any) -> None:
    if hasattr(report, "state"):
        lines = [f"Операция: {report.id}", f"Состояние: {report.state}"]
        if report.error:
            lines.append(f"{report.error.get('stage')}: {report.error.get('reason')}")
        panel(title, lines, wrap=True)
        return
    if hasattr(report, "nodes"):
        lines = [f"{node_id}: {value.get('status', value.get('outcome', 'unknown'))}"
                 for node_id, value in report.nodes.items()]
        lines.extend(report.errors)
        panel(title, lines or ["Нет новых данных"], wrap=True)
        return
    panel(title, [str(report)], wrap=True)


def _reason(exc: Exception) -> str:
    return str(exc) if str(exc) else type(exc).__name__


__all__ = ["menu_nodes", "menu_cascades"]
