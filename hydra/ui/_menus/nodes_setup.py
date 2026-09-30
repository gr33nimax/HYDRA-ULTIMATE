"""Cancelable node install wizard; no side effects until final confirmation."""

from __future__ import annotations

import json

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import checked_node_branch, checked_node_revision
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui.tui import confirm, kv, menu, panel, prompt, success


def read_protocol(name: str, app: ApplicationService, previous: NodeProtocolSpec) -> NodeProtocolSpec | None:
    supported = {
        plugin.meta.name
        for plugin in app.protocols.list(PluginCategory.TRANSPORT)
        if (plugin.meta.capabilities.subscription_enabled
            or plugin.meta.capabilities.hydra_v2_subscription_enabled)
    }
    if name not in supported:
        raise ValueError("protocol does not publish client profiles")
    enabled = menu([("1", "Включить", ""), ("2", "Выключить", ""), ("0", "Отмена", "")], name)
    if enabled == "0":
        return None
    port = prompt("Порт протокола; 0 — авто, cancel — отмена", str(previous.port))
    if port == "cancel":
        return None
    raw = prompt(
        "Публичные параметры протокола JSON (домен/IP здесь); cancel — отмена",
        json.dumps(previous.config, ensure_ascii=False),
    )
    if raw == "cancel":
        return None
    try:
        spec = NodeProtocolSpec(enabled=enabled == "1", port=int(port), config=json.loads(raw))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid protocol port or public JSON configuration") from exc
    spec.validate()
    return spec


def _input(label: str, default: str = "") -> str:
    value = prompt(f"{label} (cancel — отмена)", default)
    if value == "cancel":
        raise InterruptedError("installation canceled")
    return value


def install_node(state: AppState, app: ApplicationService) -> None:
    try:
        if not app.admin.unit_active("hydra-sub"):
            raise ValueError("base HTTPS subscription service must be active")
        cert, _ = app.admin.subscription_certificate(state)
        if not cert:
            raise ValueError("base subscription certificate is missing")
        node = NodeConfig(
            id=_input("Стабильный уникальный ID ноды"),
            address=_input("SSH / management hostname или IP"),
            ssh_port=int(_input("SSH-порт", "22")),
            name=_input("Отображаемое имя"),
            region=_input("Регион"),
            branch=checked_node_branch(_input("Ветка", "main"), context="branch"),
            revision=checked_node_revision(_input("Точный SHA коммита (40 hex)"), context="revision"),
            control_port=int(_input("Management TCP-порт", "9444")),
        )
        node.validate()
        if any(item.id == node.id for item in app.nodes.list_nodes(state)):
            raise ValueError("node ID already exists")
        while True:
            supported = [
                plugin
                for plugin in app.protocols.list(PluginCategory.TRANSPORT)
                if (plugin.meta.capabilities.subscription_enabled
                    or plugin.meta.capabilities.hydra_v2_subscription_enabled)
            ]
            options = [(plugin.meta.name, plugin.meta.display_name, "") for plugin in supported]
            options.extend([("done", "Продолжить", ""), ("0", "Отмена установки", "")])
            choice = menu(options, "ПРОТОКОЛЫ НОДЫ").lower()
            if choice == "0":
                return
            if choice == "done":
                break
            spec = read_protocol(choice, app, node.protocols.get(choice, NodeProtocolSpec()))
            if spec is not None:
                node.protocols[choice] = spec
                name = _input("Имя профиля; - = по умолчанию", "-")
                if name != "-":
                    node.profile_names[choice] = name
        node.validate()
        calls = node.protocols.get("calls")
        vk_cookie_source = None
        if calls is not None and calls.enabled:
            panel("VK COOKIES НОДЫ", [
                "Нужен отдельный JSON для этой ноды: cookies основы не копируются.",
                "Скачать WhitelistBypass.Creator: github.com/kulikov0/whitelist-bypass/releases",
                "Cookies будут импортированы по pinned SSH до первого включения VK Tunnel.",
            ], wrap=True)
            vk_cookie_source = _input("Путь к отдельному VK cookies JSON")
        host = app.admin.subscription_public_host(state)
        base_url = f"https://{host}"
        if not state.network.sub_domain:
            base_url += ":9443"
        panel(
            "ПЛАН УСТАНОВКИ",
            [
                kv("Нода:", f"{node.name} · {node.id}"),
                kv("SSH:", f"{node.address}:{node.ssh_port}"),
                kv("Management:", str(node.control_port)),
                kv("Точный SHA:", node.revision),
                kv("Протоколы:", ", ".join(node.protocols) or "нет"),
                "SSH устанавливает HYDRA; параметры содержат только публичную конфигурацию.",
                "При неполном provisioning запись/доступ требуют проверки и повторной попытки.",
            ],
            wrap=True,
        )
        if not confirm("Установить эту ноду?", default=False):
            return
        result = app.nodes.add_node(
            node,
            base_url=base_url,
            confirm_fingerprint=lambda fingerprint: confirm(f"Доверять SSH host key {fingerprint}?", default=False),
            vk_cookie_source=vk_cookie_source,
        )
        success(f"Нода установлена; экспорт: {result.status}")
    except InterruptedError:
        return
