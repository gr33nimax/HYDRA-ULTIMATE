"""Cancelable node install wizard: collect, plan, confirm, then act.

The order is the operator's: address, SSH account, password, visible ID, name, then the
protocols. Nothing touches the VPS until the plan is confirmed, and the password is not
written to state, logs or the command line — it lives only inside the one scoped channel
that OpenSSH reads while the enrollment runs.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Callable

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import checked_node_branch, checked_node_revision
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.nodes.installer import checked_ssh_user, valid_node_address
from hydra.services.nodes.ssh_auth import ssh_password_auth
from hydra.ui._menus.node_protocol_fields import (
    collect_protocol_config,
    preflight_protocol,
    protocol_field_labels,
)
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import ask, ask_secret, confirm, error, kv, menu, panel, prompt, success

NEW_NODE_HINTS = [
    "Адрес — IP или домен VPS.",
    "SSH-пользователь и пароль нужны только для установки; пароль не сохраняется.",
    "ID — видимая подпись ноды, её можно менять позже без перевыпуска ключей.",
]

# Human names for the boundaries the install actually reports.
STAGE_TEXT = {
    "ssh": "Проверка SSH-доступа и доверия",
    "install": "Установка HYDRA на VPS",
    "identity": "Подключение ноды к основе",
    "register": "Сохранение ноды",
    "publish": "Применение настроек и публикация профилей",
}
STAGE_ORDER = ("ssh", "install", "identity", "register", "publish")


@dataclass
class InstallLog:
    """Stages that really ran, so the report cannot invent progress."""

    done: list[str] = field(default_factory=list)
    failed: str = ""

    def stage(self, name: str) -> None:
        if name in STAGE_TEXT and name not in self.done:
            self.done.append(name)
            print(f"  [>>] {STAGE_TEXT[name]}")

    def failure(self, exc: BaseException) -> str:
        """The stage after the last confirmed one is the one that failed."""
        if self.failed:
            return self.failed
        remaining = [name for name in STAGE_ORDER if name not in self.done]
        self.failed = remaining[0] if remaining else "publish"
        return f"{STAGE_TEXT[self.failed]}: {exc if str(exc) else type(exc).__name__}"


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


def resolve_revision(app: ApplicationService, branch: str) -> str | None:
    try:
        return checked_node_revision(app.nodes.resolve_revision(branch), context="revision")
    except Exception:
        error("Не удалось получить SHA из GitHub. Проверь имя ветки и доступ к GitHub; операция не начата.")
        return None


def _check_subscription_ready(state: AppState, app: ApplicationService) -> None:
    if not app.admin.unit_active("hydra-sub"):
        raise ValueError("base HTTPS subscription service must be active")
    cert, _ = app.admin.subscription_certificate(state)
    if not cert:
        raise ValueError("base subscription certificate is missing")


def _ask_required(label: str, default: str = "") -> str | None:
    value = ask(f"{label} (0 — отмена)", default)
    if value is None or value == "0":
        return None
    return value.strip()


def _ask_validated(
    label: str,
    problem_of: Callable[[str], str | None],
    *,
    default: str = "",
    attempts: int = 3,
) -> str | None:
    """Ask one field until it is valid; nothing already answered is asked again."""
    for _ in range(attempts):
        value = _ask_required(label, default)
        if value is None:
            return None
        problem = problem_of(value)
        if problem is None:
            return value
        error(problem)
    error("Поле не заполнено; установка отменена")
    return None


def _address_problem(value: str) -> str | None:
    if not valid_node_address(value):
        return "Адрес не похож на IP или домен; повтори адрес"
    return None


def _ssh_user_problem(value: str) -> str | None:
    try:
        checked_ssh_user(value)
    except ValueError as exc:
        return f"{exc}; повтори имя пользователя SSH"
    return None


def _node_id_problem(app: ApplicationService, state: AppState):
    """The ID must be valid and still free; both answers keep the operator here."""

    def check(value: str) -> str | None:
        try:
            NodeConfig(id=value, address="203.0.113.1", ssh_user="root").validate()
        except ValueError as exc:
            return f"Проверь ID: {exc}"
        if any(item.id == value for item in app.nodes.list_nodes(state)):
            return "Нода с таким ID уже есть; выбери другой ID"
        return None

    return check


def _name_problem(value: str) -> str | None:
    try:
        NodeConfig(id="placeholder", address="203.0.113.1", ssh_user="root", name=value).validate()
    except ValueError as exc:
        return f"Проверь имя: {exc}"
    return None


def _collect_identity(state: AppState, app: ApplicationService) -> tuple[NodeConfig, str | None] | None:
    """The operator's exact order: address, SSH account, password, ID, name."""
    panel("НОВАЯ НОДА", NEW_NODE_HINTS, wrap=True)
    address = _ask_validated("Адрес VPS (IP или домен)", _address_problem)
    if address is None:
        return None
    ssh_user = _ask_validated("Имя пользователя SSH", _ssh_user_problem, default="root")
    if ssh_user is None:
        return None
    password = ask_secret("Пароль SSH (пусто — вход по ключу или запрос ssh)")
    if password is None:
        error("Установка отменена")
        return None
    node_id = _ask_validated("ID ноды (видимая подпись)", _node_id_problem(app, state))
    if node_id is None:
        return None
    name = _ask_validated("Имя ноды", _name_problem, default=node_id)
    if name is None:
        return None
    node = NodeConfig(id=node_id, address=address, name=name, ssh_user=ssh_user)
    try:
        node.validate()
    except ValueError as exc:
        error(f"Проверь ID и имя: {exc}")
        return None
    return node, (password or None)


def _collect_protocols(node: NodeConfig, app: ApplicationService) -> bool:
    """Collect the node's protocols; False means the operator cancelled."""
    while True:
        choices = protocol_choices(app)
        next_key = str(len(choices) + 1)
        options = [
            (key, label, "выбран" if node.protocols.get(protocol, NodeProtocolSpec()).enabled else "")
            for key, (protocol, label) in choices.items()
        ]
        options.extend([(next_key, "Готово", "перейти к проверке"), ("0", "Отмена установки", "")])
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
            name = _ask_required("Название профиля в подписке (Enter — без имени)", "")
            if name is None:
                node.protocols.pop(protocol, None)
            elif name not in ("", "-"):
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
    value = ask("Путь к отдельному VK cookies JSON (0 — без cookies)")
    if value in (None, "0"):
        return None
    return value


def _base_url(state: AppState, app: ApplicationService) -> str:
    host = app.admin.subscription_public_host(state)
    return f"https://{host}" if state.network.sub_domain else f"https://{host}:9443"


def _confirm_fingerprint(fingerprint: str) -> bool:
    return confirm(f"Доверять SSH host key {fingerprint}?", default=False)


def _plan_lines(node: NodeConfig, state: AppState, app: ApplicationService) -> list[str]:
    protocols = ", ".join(protocol_label(name) for name in sorted(node.protocols) if node.protocols[name].enabled)
    return [
        kv("ID:", node.display_id or node.id),
        kv("Имя:", node.name or node.id),
        kv("Адрес:", node.address),
        kv("SSH:", f"{node.ssh_user}@{node.address}:{node.ssh_port}"),
        kv("Пароль:", "введён, не сохраняется"),
        kv("Протоколы:", protocols or "нет"),
        kv("Ветка:", node.branch),
        kv("SHA (получен автоматически):", node.revision),
        kv("API управления:", str(node.control_port)),
        kv("Подписка:", _base_url(state, app)),
        "SSH устанавливает HYDRA; параметры содержат только публичную конфигурацию.",
    ]


def _edit_plan(node: NodeConfig, app: ApplicationService) -> None:
    """Advanced fields live here, so the normal path stays five questions long."""
    choice = menu(
        [
            ("1", "ID и имя", ""),
            ("2", "Адрес и SSH", ""),
            ("3", "Порты", ""),
            ("4", "Ветка", ""),
            ("0", "Назад", ""),
        ],
        "ИСПРАВИТЬ ДАННЫЕ",
    )
    if choice == "1":
        node_id = _ask_required("ID ноды", node.id)
        name = _ask_required("Имя ноды", node.name)
        if node_id and name:
            node.id, node.name = node_id, name
    elif choice == "2":
        address = _ask_required("Адрес VPS", node.address)
        ssh_user = _ask_required("Имя пользователя SSH", node.ssh_user)
        if address and ssh_user:
            node.address, node.ssh_user = address, ssh_user
    elif choice == "3":
        ssh_port = _ask_required("SSH-порт", str(node.ssh_port))
        control_port = _ask_required("Порт API управления", str(node.control_port))
        if ssh_port and control_port:
            try:
                node.ssh_port, node.control_port = int(ssh_port), int(control_port)
            except ValueError:
                error("Порты должны быть числами")
    elif choice == "4":
        _edit_branch(node, app)
    try:
        node.validate()
    except ValueError as exc:
        error(f"Данные не сохранены: {exc}")


def _edit_branch(node: NodeConfig, app: ApplicationService) -> None:
    """Change the branch and the commit together: a SHA belongs to its branch.

    Editing the branch alone once installed the newer branch's script against the older
    branch's tree, and the install stopped on a file that did not exist yet.
    """
    branch = _ask_required("Ветка", node.branch)
    if not branch:
        return
    try:
        candidate = checked_node_branch(branch, context="branch")
    except ValueError as exc:
        error(str(exc))
        return
    if candidate == node.branch:
        return
    resolved = resolve_revision(app, candidate)
    if resolved is None:
        error("Ветка не изменена: SHA новой ветки не получен")
        return
    node.branch, node.revision = candidate, resolved
    success(f"Ветка {candidate}, коммит {resolved[:12]}")


def _report(log: InstallLog, node: NodeConfig, result: object) -> None:
    status = getattr(result, "status", "")
    lines = [f"[OK] {STAGE_TEXT[name]}" for name in log.done]
    lines.extend([f"[OK] {STAGE_TEXT[name]}" for name in STAGE_ORDER if name not in log.done and name != log.failed])
    lines.append(f"Публикация профилей: {status}")
    panel("ОТЧЁТ ОБ УСТАНОВКЕ", [f"{node.label} · {node.address}", *lines], wrap=True)


def _offer_resume(
    node: NodeConfig,
    password: str | None,
    state: AppState,
    app: ApplicationService,
    log: InstallLog,
) -> None:
    """Continue the same node after a partial install, never reinstalling it."""
    panel(
        "ПРОДОЛЖИТЬ ПОДКЛЮЧЕНИЕ",
        [
            "Установка не повторяется: HYDRA зайдёт по pinned SSH и выдаст удостоверение.",
            "Подходит, если HYDRA на VPS уже установлена, а нода не подключилась.",
            "Версия на VPS остаётся той, что установлена: обновление — отдельный пункт.",
        ],
        wrap=True,
    )
    if not confirm("Продолжить подключение этой ноды?", default=False):
        return
    try:
        with ssh_password_auth(password) if password else nullcontext() as auth:
            result = app.nodes.resume_node(
                node,
                base_url=_base_url(state, app),
                confirm_fingerprint=_confirm_fingerprint,
                auth=auth,
                progress=log.stage,
            )
        _report(log, node, result)
    except Exception as exc:
        error(f"Подключение не завершено · {log.failure(exc)}")


def install_node(state: AppState, app: ApplicationService) -> None:
    # Checked before anything is asked: a base without a working HTTPS subscription
    # service cannot publish this node, so the operator should not type a password first.
    _check_subscription_ready(state, app)
    node: NodeConfig | None = None
    password: str | None = None
    log = InstallLog()
    try:
        collected = _collect_identity(state, app)
        if collected is None:
            return
        node, password = collected
        if not _collect_protocols(node, app):
            return
        vk_cookie_source = _collect_calls_cookies(node)
        revision = resolve_revision(app, node.branch)
        if revision is None:
            return
        node.revision = revision
        while True:
            panel("ПЛАН УСТАНОВКИ", _plan_lines(node, state, app), wrap=True)
            choice = menu(
                [
                    ("1", "Подтвердить установку", ""),
                    ("2", "Исправить данные", ""),
                    ("0", "Отмена", ""),
                ],
                "ПОДТВЕРЖДЕНИЕ",
            )
            if choice == "2":
                _edit_plan(node, app)
                continue
            if choice != "1":
                error("Установка отменена; VPS не изменялась")
                return
            break
        panel("УСТАНОВКА", ["Установка начата. Этапы отмечаются по мере выполнения."], wrap=True)
        with ssh_password_auth(password) if password else nullcontext() as auth:
            result = app.nodes.add_node(
                node,
                base_url=_base_url(state, app),
                confirm_fingerprint=_confirm_fingerprint,
                vk_cookie_source=vk_cookie_source,
                auth=auth,
                progress=log.stage,
            )
        _report(log, node, result)
    except InterruptedError:
        return
    except Exception as exc:
        error(f"Установка не завершена · {log.failure(exc)}")
        # A runtime failure from the provisioning path may have left HYDRA installed, so
        # continuing the same node is offered instead of a second install. Continuing
        # verifies ownership over the pinned SSH key and refuses when nothing is there,
        # which is why the offer does not depend on knowing the exact remote state.
        if node is not None and isinstance(exc, RuntimeError):
            _offer_resume(node, password, state, app, log)
            return
        panel(
            "ЧТО ДАЛЬШЕ",
            [
                "Повторный запуск установки для уже установленной ноды не требуется.",
                "Если HYDRA на VPS уже стоит, используй продолжение подключения той же ноды.",
            ],
            wrap=True,
        )


__all__ = [
    "STAGE_ORDER",
    "STAGE_TEXT",
    "InstallLog",
    "install_node",
    "protocol_choices",
    "read_protocol",
    "resolve_revision",
]
