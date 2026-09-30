"""Cancelable node install wizard; no side effects until final confirmation."""

from __future__ import annotations

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import checked_node_branch, checked_node_revision
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.node_protocol_fields import collect_protocol_config, missing_required, protocol_field_labels
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import confirm, error, kv, menu, panel, prompt, success


NEW_NODE_HINTS = [
    "ID — постоянный ключ ноды в state, например uk-1; имя можно менять потом.",
    "Название — подпись ноды в списке и подписках, не SSH-логин.",
    "Адрес — IP или домен VPS; HYDRA заходит по SSH под root.",
    "Регион — необязательная подпись в подписке.",
    "SHA ветки мастер получит сам и покажет перед установкой.",
]


def protocol_choices(app: ApplicationService) -> dict[str, tuple[str, str]]:
    supported = [
        plugin
        for plugin in app.protocols.list(PluginCategory.TRANSPORT)
        if (plugin.meta.capabilities.subscription_enabled or plugin.meta.capabilities.hydra_v2_subscription_enabled)
    ]
    return {
        str(index): (plugin.meta.name, protocol_label(plugin.meta.name, getattr(plugin.meta, "display_name", "")))
        for index, plugin in enumerate(supported, 1)
    }


def read_protocol(name: str, app: ApplicationService, previous: NodeProtocolSpec) -> NodeProtocolSpec | None:
    supported = dict(protocol_choices(app).values())
    if name not in supported:
        raise ValueError("protocol does not publish client profiles")
    enabled = menu([("1", "Включить", ""), ("2", "Выключить", ""), ("0", "Отмена", "")], supported[name])
    if enabled not in {"1", "2"}:
        return None
    if enabled == "2":
        spec = NodeProtocolSpec(enabled=False, port=previous.port, config=dict(previous.config))
        spec.validate()
        return spec
    port_mode = menu(
        [("1", "Автоматический порт", ""), ("2", "Указать порт вручную", ""), ("0", "Отмена", "")],
        "ПОРТ ПРОТОКОЛА НА НОДЕ",
    )
    if port_mode not in {"1", "2"}:
        return None
    try:
        port = (
            int(_input("Порт протокола на этой ноде (1–65535)", str(previous.port) if previous.port else ""))
            if port_mode == "2"
            else 0
        )
    except (InterruptedError, ValueError):
        return None
    if port and not 1 <= port <= 65535:
        error("Порт протокола: допустимо от 1 до 65535")
        return None
    config = collect_protocol_config(name, dict(previous.config))
    if config is None:
        return None
    required = "" if name == "vless" and config.get("security") == "reality" else missing_required(name, config)
    if required:
        error(f"{required}: значение обязательно для {supported[name]}")
        return None
    if name == "vless" and config.get("security") != "reality" and not str(config.get("domain", "")).strip():
        error("VLESS в режиме TLS требует домен")
        return None
    spec = NodeProtocolSpec(enabled=True, port=port, config=config)
    spec.validate()
    labels = protocol_field_labels(name)
    panel(
        f"{supported[name].upper()} · ПАРАМЕТРЫ",
        [kv("Порт:", "авто" if not port else str(port))]
        + [kv(f"{labels.get(key, key)}:", str(value)) for key, value in sorted(config.items())],
        wrap=True,
    )
    return spec


def _input(label: str, default: str = "") -> str:
    value = prompt(f"{label} (0 — отмена)", default)
    if value in {"0", "cancel"}:
        raise InterruptedError("installation canceled")
    return value


def resolve_revision(app: ApplicationService, branch: str) -> str | None:
    try:
        return checked_node_revision(app.nodes.resolve_revision(branch), context="revision")
    except Exception:
        error("Не удалось получить SHA из GitHub. Проверь имя ветки и доступ к GitHub; операция не начата.")
        return None


def install_node(state: AppState, app: ApplicationService) -> None:
    try:
        if not app.admin.unit_active("hydra-sub"):
            raise ValueError("base HTTPS subscription service must be active")
        cert, _ = app.admin.subscription_certificate(state)
        if not cert:
            raise ValueError("base subscription certificate is missing")
        panel("НОВАЯ НОДА", NEW_NODE_HINTS, wrap=True)
        node_id = _input("ID ноды", "")
        node = NodeConfig(
            id=node_id,
            address=_input("Адрес VPS (IP или домен)"),
            ssh_port=int(_input("SSH-порт", "22")),
            name=_input("Название ноды", node_id),
            region=_input("Регион", ""),
            branch=checked_node_branch(_input("Ветка", "main"), context="branch"),
            control_port=int(_input("Порт API управления", "9444")),
        )
        node.validate()
        if any(item.id == node.id for item in app.nodes.list_nodes(state)):
            raise ValueError("node ID already exists")
        while True:
            choices = protocol_choices(app)
            next_key = str(len(choices) + 1)
            options = [
                (key, label, "выбран" if node.protocols.get(protocol, NodeProtocolSpec()).enabled else "")
                for key, (protocol, label) in choices.items()
            ]
            options.extend([(next_key, "Продолжить", ""), ("0", "Отмена установки", "")])
            choice = menu(options, "ПРОТОКОЛЫ НОДЫ")
            if choice == "0":
                return
            if choice == next_key:
                break
            selected = choices.get(choice)
            if selected is None:
                continue
            protocol, _ = selected
            spec = read_protocol(protocol, app, node.protocols.get(protocol, NodeProtocolSpec()))
            if spec is not None:
                node.protocols[protocol] = spec
                name = _input("Название профиля в подписке", "-")
                if name != "-":
                    node.profile_names[protocol] = name
        node.validate()
        calls = node.protocols.get("calls")
        vk_cookie_source = None
        if calls is not None and calls.enabled:
            panel(
                "VK COOKIES НОДЫ",
                [
                    "Нужен отдельный JSON для этой ноды: cookies основы не копируются.",
                    "Скачать WhitelistBypass.Creator: github.com/kulikov0/whitelist-bypass/releases",
                    "Cookies будут импортированы по pinned SSH до первого включения VK Tunnel.",
                ],
                wrap=True,
            )
            vk_cookie_source = _input("Путь к отдельному VK cookies JSON")
        revision = resolve_revision(app, node.branch)
        if revision is None:
            return
        node.revision = revision
        host = app.admin.subscription_public_host(state)
        base_url = f"https://{host}"
        if not state.network.sub_domain:
            base_url += ":9443"
        panel(
            "ПЛАН УСТАНОВКИ",
            [
                kv("Нода:", f"{node.name} · {node.id}"),
                kv("SSH:", f"root@{node.address}:{node.ssh_port}"),
                kv("API управления:", str(node.control_port)),
                kv("Ветка:", node.branch),
                kv("SHA (получен автоматически):", node.revision),
                kv(
                    "Протоколы:",
                    ", ".join(dict(choices.values()).get(name, protocol_label(name)) for name in node.protocols)
                    or "нет",
                ),
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
