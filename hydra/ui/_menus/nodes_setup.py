"""ApplicationService-backed managed-node enrollment wizard."""

from __future__ import annotations

import ipaddress
from contextlib import nullcontext
from typing import Callable

from hydra.contracts.managed_node_installation import InstallPlan, InstallRequest
from hydra.contracts.managed_node_models import Operation, ProtocolAssignment
from hydra.services.managed_nodes.credentials import SshPasswordChannel
from hydra.ui._menus.node_protocol_fields import PROTOCOL_FIELDS, collect_protocol_config
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import ask, ask_secret, confirm, error, kv, menu, panel, success

def _required(label: str, default: str = "") -> str | None:
    value = ask(label, default)
    if value is None or value.strip() == "0":
        return None
    value = value.strip()
    if not value:
        error(f"{label}: значение обязательно")
        return None
    return value


def _collect_protocols(app) -> list[ProtocolAssignment] | None:
    from hydra.plugins.base import PluginCategory

    plugins = [
        plugin for plugin in app.protocols.list(PluginCategory.TRANSPORT)
        if plugin.meta.name in PROTOCOL_FIELDS
        and (plugin.meta.capabilities.subscription_enabled or plugin.meta.capabilities.hydra_v2_subscription_enabled)
    ]
    selected: dict[str, ProtocolAssignment] = {}
    while True:
        choices = {
            str(index): plugin
            for index, plugin in enumerate(plugins, 1)
        }
        options = [
            (key, protocol_label(plugin.meta.name, getattr(plugin.meta, "display_name", "")),
             "настроен" if plugin.meta.name in selected else "")
            for key, plugin in choices.items()
        ]
        options.extend([(str(len(options) + 1), "Продолжить", ""), ("0", "Отмена установки", "")])
        choice = menu(options, "ПРОТОКОЛЫ НОДЫ")
        if choice == "0":
            return None
        if choice == str(len(choices) + 1):
            if selected:
                return list(selected.values())
            error("Выбери хотя бы один протокол")
            continue
        plugin = choices.get(choice)
        if plugin is None:
            continue
        name = plugin.meta.name
        previous = selected[name].parameters if name in selected else {}
        config = collect_protocol_config(name, previous)
        if config is None:
            continue
        if not any(key == "port" or key.endswith("_port") for key in config):
            config["port"] = 443
        selected[name] = ProtocolAssignment(name, config)


def install_node(state, app) -> Operation | None:
    """Collect, pin, plan and explicitly confirm before installation side effects."""
    node_id = _required("ID ноды")
    name = _required("Имя ноды", node_id or "") if node_id else None
    address = _required("IP-адрес ноды") if name else None
    ssh_user = _required("Пользователь SSH", "root") if address else None
    if node_id is None or name is None or address is None or ssh_user is None:
        return None
    try:
        ipaddress.ip_address(address)
        if node_id == "base":
            raise ValueError("ID base зарезервирован для основы")
    except ValueError as exc:
        error(f"Некорректные данные ноды: {exc}")
        return None
    ssh_port_raw = _required("SSH-порт", "22")
    if ssh_port_raw is None or not ssh_port_raw.isdecimal() or not 1 <= int(ssh_port_raw) <= 65535:
        error("Некорректный SSH-порт")
        return None
    ssh_port = int(ssh_port_raw)
    password = ask_secret("Пароль SSH (пусто — использовать SSH-ключ)")
    if password is None:
        return None
    branch = {"1": "main", "2": "dev"}.get(menu(
        [("1", "main", "стабильная ветка"), ("2", "dev", "ветка разработки"), ("0", "Отмена", "")],
        "ВЕТКА ДО НАСТРОЙКИ ПРОТОКОЛОВ",
    ))
    if branch is None:
        return None
    port_mode = menu(
        [("1", "Выбрать свободный случайный порт", "будет сохранён в плане"),
         ("2", "Задать порт вручную", ""), ("0", "Отмена", "")],
        "ПОРТ УПРАВЛЕНИЯ",
    )
    if port_mode == "0":
        return None
    control_port = None
    if port_mode == "2":
        raw_port = _required("TCP-порт управления (1024–65535)")
        if raw_port is None or not raw_port.isdecimal() or not 1024 <= int(raw_port) <= 65535:
            error("Порт управления должен быть числом от 1024 до 65535")
            return None
        control_port = int(raw_port)
    protocols = _collect_protocols(app)
    if protocols is None:
        return None
    auth_context = SshPasswordChannel(password) if password else nullcontext(None)
    try:
        with auth_context as auth:
            fingerprint = app.nodes.discover_host_key(address, ssh_port)
            if not confirm(f"Доверять SSH host key {fingerprint}?", default=False):
                return None
            request = InstallRequest(
                node_id, name, address, ssh_user, branch, protocols,
                fingerprint, control_port, ssh_port,
            )
            plan = app.nodes.plan(request, auth)
            if not _confirm_plan(plan, len(state.users)):
                return None
            reinstall = False
            if plan.existing_installation:
                reinstall = confirm("Следующая операция переустановит HU с нуля. Продолжить?", default=False)
                if not reinstall:
                    return None
            return app.nodes.install(plan, auth, True, reinstall, progress=_progress)
    except Exception as exc:
        error(f"Установка не завершена: {exc if str(exc) else type(exc).__name__}")
        return None


def _confirm_plan(plan: InstallPlan, user_count: int) -> bool:
    definition = plan.definition
    panel("ПЛАН УСТАНОВКИ", [
        kv("ID:", definition.id), kv("Имя:", definition.name),
        kv("Адрес:", definition.address), kv("SSH:", f"{definition.ssh_user}:{definition.ssh_port}"),
        kv("Ветка:", definition.branch), kv("Ревизия:", definition.revision),
        kv("Управление:", str(definition.control_port)),
        kv("Протоколы:", ", ".join(protocol_label(item.name) for item in definition.protocols)),
        kv("Пользователи:", f"{user_count} (будут синхронизированы с основы)"),
        *(plan.warnings),
        "Пароль SSH не сохраняется.",
    ], wrap=True)
    return confirm("Подтвердить установку?", default=False)


def _progress(event: dict[str, str]) -> None:
    state = event.get("state")
    step = event.get("step")
    reason = event.get("reason", "")
    if state == "succeeded":
        success(f"Этап {step} подтверждён")
    elif state in {"failed", "recovery_required"}:
        error(f"Этап {step}: {reason or state}")


__all__ = ["install_node"]
