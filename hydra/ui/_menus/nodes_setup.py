"""Cancelable node install wizard; no side effects until final confirmation."""

from __future__ import annotations

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import checked_node_branch, checked_node_revision
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.node_protocol_fields import (
    collect_protocol_config,
    preflight_protocol,
    protocol_field_labels,
)
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
    config = collect_protocol_config(name, dict(previous.config))
    if config is None:
        return None
    problem = preflight_protocol(name, config)
    if problem:
        error(f"{problem} ({supported[name]})")
        return None
    spec = NodeProtocolSpec(enabled=True, port=previous.port, config=config)
    spec.validate()
    labels = protocol_field_labels(name)
    panel(
        f"{supported[name].upper()} · ПАРАМЕТРЫ",
        [kv(f"{labels.get(key, key)}:", str(value)) for key, value in sorted(config.items())],
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


RESUME_HINTS = [
    "Для VPS, где HYDRA уже установлена, но удостоверение ноды не выдано.",
    "Установка НЕ повторяется: HYDRA заходит по pinned SSH и выдаёт удостоверение.",
    "Если HYDRA на VPS нет — добавь ноду как новую.",
]


def _check_subscription_ready(state: AppState, app: ApplicationService) -> None:
    if not app.admin.unit_active("hydra-sub"):
        raise ValueError("base HTTPS subscription service must be active")
    cert, _ = app.admin.subscription_certificate(state)
    if not cert:
        raise ValueError("base subscription certificate is missing")


def _collect_identity(state: AppState, app: ApplicationService, *, title: str, hints: list[str]) -> NodeConfig:
    """Ask for the facts every node needs, whether it is installed or only resumed."""
    panel(title, hints, wrap=True)
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
    return node


def _collect_protocols(node: NodeConfig, app: ApplicationService) -> bool:
    """Collect the node's protocols; False means the operator cancelled."""
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
            return False
        if choice == next_key:
            node.validate()
            return True
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


def _collect_calls_cookies(node: NodeConfig) -> str | None:
    """A node that serves Calls needs its own cookie file, imported before first enable."""
    calls = node.protocols.get("calls")
    if calls is None or not calls.enabled:
        return None
    panel(
        "VK COOKIES НОДЫ",
        [
            "Нужен отдельный JSON для этой ноды: cookies основы не копируются.",
            "Скачать WhitelistBypass.Creator: github.com/kulikov0/whitelist-bypass/releases",
            "Cookies будут импортированы по pinned SSH до первого включения VK Tunnel.",
        ],
        wrap=True,
    )
    return _input("Путь к отдельному VK cookies JSON")


def _base_url(state: AppState, app: ApplicationService) -> str:
    host = app.admin.subscription_public_host(state)
    return f"https://{host}" if state.network.sub_domain else f"https://{host}:9443"


def _confirm_fingerprint(fingerprint: str) -> bool:
    return confirm(f"Доверять SSH host key {fingerprint}?", default=False)


def install_node(state: AppState, app: ApplicationService) -> None:
    try:
        _check_subscription_ready(state, app)
        node = _collect_identity(state, app, title="НОВАЯ НОДА", hints=NEW_NODE_HINTS)
        if not _collect_protocols(node, app):
            return
        vk_cookie_source = _collect_calls_cookies(node)
        revision = resolve_revision(app, node.branch)
        if revision is None:
            return
        node.revision = revision
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
                    ", ".join(protocol_label(name) for name in node.protocols) or "нет",
                ),
                "SSH устанавливает HYDRA; параметры содержат только публичную конфигурацию.",
                "При неполном provisioning запись/доступ требуют проверки и повторной попытки.",
            ],
            wrap=True,
        )
        if not confirm("Установить эту ноду?", default=False):
            return
        base_url = _base_url(state, app)
        try:
            result = app.nodes.add_node(
                node,
                base_url=base_url,
                confirm_fingerprint=_confirm_fingerprint,
                vk_cookie_source=vk_cookie_source,
            )
        except RuntimeError as exc:
            # A VPS that already carries HYDRA refuses a second install, and a node whose
            # control identity never arrived has no record to open. Both are recoverable
            # without reinstalling, so the offer is made here, with the data already
            # collected, instead of asking the operator to retype everything.
            error(str(exc))
            panel(
                "ПРОДОЛЖИТЬ ПОДКЛЮЧЕНИЕ",
                [
                    "Установка не повторяется: HYDRA заходит по pinned SSH и выдаёт удостоверение.",
                    "Подходит, если HYDRA на VPS уже установлена, а нода не подключилась.",
                    "Версия на VPS остаётся той, что установлена: обновление — отдельный пункт.",
                ],
                wrap=True,
            )
            if not confirm("Продолжить подключение этой ноды?", default=False):
                return
            result = app.nodes.resume_node(
                node,
                base_url=base_url,
                confirm_fingerprint=_confirm_fingerprint,
                vk_cookie_source=vk_cookie_source,
            )
        success(f"Нода готова; экспорт: {result.status}")
    except InterruptedError:
        return
