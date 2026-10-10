"""Protocol settings, profile names and removal for one managed node."""
from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

from hydra.contracts.managed_node_models import ProtocolAssignment
from hydra.contracts.managed_node_observations import NodeView
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.node_protocol_fields import (
    PROTOCOL_FIELDS, collect_protocol_config, preflight_protocol, protocol_config_changed,
)
from hydra.ui._menus.users_names import edit_global_configuration_names
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import confirm, error, menu, success

ReportRenderer = Callable[[str, Any], None]


def manage_node_protocols(view: NodeView, app: ApplicationService, show_report: ReportRenderer) -> None:
    current = {item.name: item for item in view.definition.protocols}
    while True:
        names = sorted(current)
        options = [(str(index), protocol_label(name), "настройки, название и удаление")
                   for index, name in enumerate(names, 1)]
        add_key = str(len(options) + 1)
        options.extend([(add_key, "Добавить протокол", ""), ("0", "Назад", "")])
        choice = menu(options, "ПРОТОКОЛЫ НОДЫ")
        if choice == "0":
            return
        if choice == add_key:
            if _add_protocol(view, app, set(current), show_report):
                return
        elif choice.isdecimal() and 1 <= int(choice) <= len(names):
            assignment = current[names[int(choice) - 1]]
            if _protocol_settings(view, assignment, app, show_report):
                return


def _protocol_settings(
    view: NodeView, assignment: ProtocolAssignment, app: ApplicationService, show_report: ReportRenderer,
) -> bool:
    label = protocol_label(assignment.name)
    while True:
        choice = menu([
            ("1", "Изменить настройки", ""),
            ("2", "Название конфигурации", "как профиль называется в подписках"),
            ("3", "Удалить протокол", "отключить на ноде и убрать его профили из подписок"),
            ("0", "Назад", ""),
        ], f"{label} · {view.definition.name}")
        if choice == "0":
            return False
        if choice == "1":
            if _edit_protocol(view, assignment, app, show_report, adding=False):
                return True
        elif choice == "2":
            edit_global_configuration_names(app.admin.load_state(), app,
                                            node_id=view.definition.id, protocol_name=assignment.name)
        elif choice == "3" and confirm(
            f"Удалить {label} на ноде {view.definition.name}? Его профили исчезнут из подписок.", default=False,
        ):
            report = app.nodes.remove_protocol(view.definition.id, assignment.name, confirmed=True)
            show_report("УДАЛЕНИЕ ПРОТОКОЛА", report)
            return True


def _add_protocol(view: NodeView, app: ApplicationService, configured: set[str], show_report: ReportRenderer) -> bool:
    available = [item for item in app.protocols.list(PluginCategory.TRANSPORT)
                 if item.meta.name in PROTOCOL_FIELDS and item.meta.name not in configured
                 and (item.meta.capabilities.subscription_enabled or item.meta.capabilities.hydra_v2_subscription_enabled)]
    choice = menu([
        (str(index), protocol_label(item.meta.name, getattr(item.meta, "display_name", "")), "")
        for index, item in enumerate(available, 1)
    ] + [("0", "Назад", "")], "ДОБАВИТЬ ПРОТОКОЛ")
    if not choice.isdecimal() or not 1 <= int(choice) <= len(available):
        return False
    assignment = ProtocolAssignment(available[int(choice) - 1].meta.name, {})
    return _edit_protocol(view, assignment, app, show_report, adding=True)


def _edit_protocol(
    view: NodeView, before: ProtocolAssignment, app: ApplicationService, show_report: ReportRenderer, *, adding: bool,
) -> bool:
    parameters = collect_protocol_config(before.name, deepcopy(before.parameters))
    if parameters is None:
        return False
    if not any(key == "port" or key.endswith("_port") for key in parameters):
        parameters["port"] = 443
    if not adding and not protocol_config_changed(before.name, before.parameters, parameters):
        success("Настройки не изменились.")
        return False
    problem = preflight_protocol(before.name, parameters)
    if problem:
        error(problem)
        return False
    if not confirm(f"Применить настройки {protocol_label(before.name)} на ноде {view.definition.name}?", default=False):
        return False
    report = app.nodes.configure_protocol(view.definition.id, ProtocolAssignment(before.name, parameters), confirmed=True)
    if report is not None:
        show_report("НАСТРОЙКИ ПРОТОКОЛА", report)
    return True
