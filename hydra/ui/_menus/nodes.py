"""Base-side node management: all effects go through ApplicationService."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.application import ApplicationService
from hydra.services.nodes.observation import CONTROL_ERROR, CONTROL_UNKNOWN
from hydra.ui._menus.nodes_setup import install_node, protocol_choices, read_protocol, resolve_revision
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import clear, confirm, error, kv, menu, panel, prompt, success


def remove_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "УДАЛЕНИЕ НОДЫ",
        [
            kv("Нода:", node.name or node.id),
            kv("SSH:", f"{node.address}:{node.ssh_port}"),
            "Будут удалены принадлежащие HYDRA службы, программа и данные на ноде.",
            "Локальная запись удаляется только после подтверждённой очистки по SSH.",
        ],
        wrap=True,
    )
    if prompt("Введите точное имя ноды для удаления") != (node.name or node.id):
        error("Имя не совпало; удаление отменено")
        return False
    if not confirm("Очистить HYDRA на этой VPS?", default=False):
        return False
    result = app.nodes.remove_node(node.id, confirmed=True)
    success("Нода удалена")
    warnings = result.get("cleanup_warnings", [])
    if isinstance(warnings, list):
        for warning in warnings:
            error(f"Локальная очистка требует внимания: {warning}")
    return True


def detach_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "ОТСОЕДИНЕНИЕ БЕЗ ОЧИСТКИ VPS",
        [
            kv("Нода:", node.name or node.id),
            "Будут удалены запись, публикация и credentials только на основе.",
            "VPS НЕ остановлена: старые клиенты могут продолжать работать.",
            "Удалённо отозвать доступ без связи невозможно; очисти VPS отдельно.",
            "Уже учтённый трафик останется в общей квоте.",
        ],
        wrap=True,
    )
    if prompt("Введите точное имя отсоединяемой ноды") != (node.name or node.id):
        error("Имя не совпало; отсоединение отменено")
        return False
    if not confirm("Отсоединить без остановки и удалённой очистки?", default=False):
        return False
    result = app.nodes.detach_node(node.id, confirmed=True)
    success("Нода отсоединена от основы; удалённая VPS не очищена")
    warnings = result.get("cleanup_warnings", [])
    if isinstance(warnings, list):
        for warning in warnings:
            error(f"Локальная очистка требует внимания: {warning}")
    return True


def _import_vk_cookies(node: NodeConfig, app: ApplicationService) -> None:
    panel(
        "VK COOKIES НОДЫ",
        [
            kv("Нода:", node.name or node.id),
            "Выбери отдельный JSON-файл; cookies основы автоматически не копируются.",
            "Импорт по pinned SSH заменяет cookies только на этой ноде.",
            "Звонки не создаются и существующий пул не пересоздаётся.",
            "WhitelistBypass.Creator: github.com/kulikov0/whitelist-bypass/releases",
        ],
        wrap=True,
    )
    source = prompt("Путь к отдельному VK cookies JSON (0 — отмена)")
    if source == "0":
        return
    if confirm("Передать cookies только этой ноде?", default=False):
        app.nodes.import_vk_cookies(node.id, source)
        success("Cookies импортированы на ноду; пул звонков не изменён")


def _protocols(node: NodeConfig, app: ApplicationService) -> None:
    app.nodes.check(node.id)
    while True:
        choices = {str(index): name for index, name in enumerate(node.protocols, 1)}
        add_key = str(len(choices) + 1)
        labels = dict(protocol_choices(app).values())
        options = [
            (key, labels.get(name, protocol_label(name)), "включён" if node.protocols[name].enabled else "выключен")
            for key, name in choices.items()
        ]
        options.extend([(add_key, "Добавить протокол", ""), ("0", "Назад", "")])
        choice = menu(options, "ПРОТОКОЛЫ НОДЫ")
        if choice == "0":
            return
        if choice == add_key:
            available = protocol_choices(app)
            options = [(key, label, "") for key, (_, label) in available.items()]
            options.append(("0", "Назад", ""))
            selected = available.get(menu(options, "ДОБАВИТЬ ПРОТОКОЛ"))
            name = selected[0] if selected is not None else None
        else:
            name = choices.get(choice)
        if name is None:
            continue
        spec = read_protocol(name, app, node.protocols.get(name, NodeProtocolSpec()))
        if spec is not None and confirm("Применить на ноде и обновить подписки?", default=False):
            app.nodes.change_protocol(node.id, name, spec)
            success("Протокол применён и экспорт подтверждён")
            return


def _profile_name(node: NodeConfig, app: ApplicationService) -> None:
    keys = set(node.protocols) | set(node.profile_names)
    state = app.admin.load_state()
    export = app.nodes.published_export(state, node.id)
    if export is not None:
        for user in export.users.values():
            for profile in user.profiles:
                keys.add(f"{profile.protocol}:{profile.profile}" if profile.profile else profile.protocol)
    choices = {str(index): key for index, key in enumerate(sorted(keys), 1)}
    options = [(number, key, node.profile_names.get(key, "")) for number, key in choices.items()]
    options.append(("0", "Назад", ""))
    key = choices.get(menu(options, "ИМЯ ПРОФИЛЯ НОДЫ"))
    if key is None:
        return
    value = prompt("Новое имя; - убирает override", node.profile_names.get(key, ""))
    app.nodes.change_profile_name(node.id, key, "" if value == "-" else value)
    success("Имя сохранено на основе; связь с нодой не требуется")


def _upgrade(node: NodeConfig, app: ApplicationService) -> None:
    branch = prompt("Ветка (0 — отмена)", node.branch)
    if branch == "0":
        return
    revision = resolve_revision(app, branch)
    if revision is None:
        return
    panel(
        "ПЛАН ОБНОВЛЕНИЯ НОДЫ",
        [kv("Нода:", node.name or node.id), kv("Ветка:", branch), kv("SHA (получен автоматически):", revision)],
        wrap=True,
    )
    if not confirm(f"Запланировать обновление {node.id} до {revision}?", default=False):
        return
    app.nodes.change_update_target(node.id, branch=branch, revision=revision)
    result = app.nodes.update(node.id)
    success(f"Обновление {result['status']}; это не подтверждение завершения")


def _publication_row(node: NodeConfig) -> str:
    """Subscription inclusion depends on a confirmed export, not on reachability."""
    if node.published_generation <= 0 or not node.published_digest:
        return "профили не опубликованы"
    if node.generation > node.published_generation:
        return f"опубликовано поколение {node.published_generation}; ждёт подтверждения {node.generation}"
    return f"опубликовано поколение {node.published_generation}"


# Names for the stages an operation can fail at: a reason is useless without knowing
# which step of the way to a working subscription failed.
STAGE_LABELS = {
    "connect": "связь",
    "apply": "применение настроек",
    "export": "подготовка профилей",
    "publish": "публикация",
    "upgrade": "обновление",
}


def _observations(app: ApplicationService) -> dict[str, Any]:
    """Last known runtime state per node; an unavailable store reads as none."""
    try:
        found = app.nodes.observations()
    except Exception:
        return {}
    return found if isinstance(found, dict) else {}


def _age(stamp: object) -> str:
    """Human age of a timestamp, or an empty string when there is none to trust."""
    if not isinstance(stamp, str) or not stamp:
        return ""
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    seconds = (datetime.now(timezone.utc) - moment).total_seconds()
    if seconds < 0:
        return "только что"
    if seconds < 90:
        return f"{int(seconds)} с назад"
    if seconds < 5400:
        return f"{int(seconds // 60)} мин назад"
    if seconds < 172800:
        return f"{int(seconds // 3600)} ч назад"
    return f"{int(seconds // 86400)} дн назад"


def _connection_row(observation: object | None) -> str:
    """Reachability and the operation outcome, kept apart from each other."""
    control = getattr(observation, "control", CONTROL_UNKNOWN)
    age = _age(getattr(observation, "checked_at", ""))
    if control == CONTROL_UNKNOWN or not isinstance(control, str):
        return "не проверялась"
    if control == CONTROL_ERROR:
        stage = str(getattr(observation, "stage", "") or "")
        if stage == "connect":
            return f"нет связи · {age}" if age else "нет связи"
        label = STAGE_LABELS.get(stage, stage or "операция")
        return f"есть связь, но {label} не выполнено · {age}" if age else f"есть связь, но {label} не выполнено"
    return f"доступна · {age}" if age else "доступна"


def _reason_row(observation: object | None) -> str:
    message = str(getattr(observation, "message", "") or "")
    if not message:
        return ""
    stage = str(getattr(observation, "stage", "") or "")
    return f"{STAGE_LABELS.get(stage, stage or 'операция')}: {message}"


def _coverage_row(node: NodeConfig, observation: object | None) -> str:
    base = _publication_row(node)
    coverage = getattr(observation, "coverage", None)
    if not isinstance(coverage, dict) or not coverage:
        return base
    counts = ", ".join(f"{name}: {count}" for name, count in sorted(coverage.items()))
    return f"{base} · {counts}"


def _node_summary(node: NodeConfig, observation: object | None) -> str:
    """One line per node in the list: what the operator needs before opening it."""
    if node.published_generation <= 0 or not node.published_digest:
        control = getattr(observation, "control", CONTROL_UNKNOWN)
        stage = str(getattr(observation, "stage", "") or "")
        if control == CONTROL_ERROR and stage == "connect":
            return "нет связи · профили не опубликованы"
        return "профили не опубликованы"
    return f"готова · поколение {node.published_generation}"


def node_card(node: NodeConfig, app: ApplicationService) -> None:
    while True:
        state = app.admin.load_state()
        current = next((item for item in app.nodes.list_nodes(state) if item.id == node.id), None)
        if current is None:
            return
        node = current
        observation = _observations(app).get(node.id)
        reason = _reason_row(observation)
        clear()
        panel(
            "НОДА",
            [
                kv("Имя:", node.name or node.id),
                kv("Регион:", node.region),
                kv("Адрес управления:", f"{node.address}:{node.control_port}"),
                kv("Связь:", _connection_row(observation)),
                kv("Экспорт в подписки:", _coverage_row(node, observation)),
                *([kv("Последняя ошибка:", reason)] if reason else []),
                kv("Ветка/SHA:", f"{node.branch} / {node.revision}"),
                "Офлайн блокировки и общие квоты применяются с задержкой.",
            ],
            wrap=True,
        )
        uses_calls = bool(node.protocols.get("calls") and node.protocols["calls"].enabled)
        options = [
            ("1", "Имя и регион", "работает офлайн"),
            ("2", "Протоколы и профили", "требуется связь"),
            ("3", "Имена профилей", "работает офлайн"),
            ("4", "Проверить связь и диагностику", "только чтение"),
            ("5", "Сверить и обновить экспорт", "профили в подписках"),
            ("6", "Обновить программу", "точный SHA"),
            ("9", "Опасные действия", "удаление или отсоединение"),
            ("0", "Назад", ""),
        ]
        if uses_calls:
            # VK cookies belong to Calls; no other node has a pool to feed.
            options.insert(6, ("8", "Импорт VK cookies ноды", "отдельный JSON по SSH"))
        choice = menu(options, "УПРАВЛЕНИЕ НОДОЙ")
        if choice == "0":
            return
        try:
            if choice == "1":
                name = prompt("Имя (0 — отмена)", node.name)
                if name != "0":
                    region = prompt("Регион", node.region)
                    app.nodes.change_name(node.id, name, region=region)
                    success("Имя сохранено")
            elif choice == "2":
                _protocols(node, app)
            elif choice == "3":
                _profile_name(node, app)
            elif choice == "4":
                result = app.nodes.check(node.id)
                panel(
                    "ДИАГНОСТИКА",
                    [
                        kv("Контракт:", str(result["contract_version"])),
                        kv("Ошибка:", str(result.get("last_error") or "нет")),
                    ],
                )
                prompt("Нажмите Enter")
            elif choice == "5":
                result = app.nodes.refresh(node.id, force=True)
                success(f"Сверка: {result.status}")
            elif choice == "6":
                _upgrade(node, app)
            elif choice == "8":
                _import_vk_cookies(node, app)
            elif choice == "9":
                _dangerous(node, app)
        except Exception as exc:
            error(f"Операция не выполнена: {type(exc).__name__}")


def _dangerous(node: NodeConfig, app: ApplicationService) -> None:
    """Destructive node operations, kept behind their own choice."""
    choice = menu(
        [
            ("1", "Отсоединить без очистки VPS", "VPS продолжит работать"),
            ("2", "Удалить ноду", "очистка по SSH"),
            ("0", "Назад", ""),
        ],
        "ОПАСНЫЕ ДЕЙСТВИЯ",
    )
    if choice == "1" and detach_node(node, app):
        raise _NodeGone
    if choice == "2" and remove_node(node, app):
        raise _NodeGone


class _NodeGone(Exception):
    """Signals that the node no longer exists, so its card must close."""


def menu_nodes(state: AppState, app: ApplicationService) -> None:
    del state
    while True:
        state = app.admin.load_state()
        listed = app.nodes.list_nodes(state)
        observations = _observations(app)
        clear()
        choices = {str(index): item for index, item in enumerate(listed, 2)}
        options = [("1", "Установить ноду", "SSH + mTLS")]
        options.extend(
            (key, item.name or item.id, f"{item.region} · {_node_summary(item, observations.get(item.id))}")
            for key, item in choices.items()
        )
        options.append(("0", "Назад", ""))
        choice = menu(options, "НОДЫ")
        if choice == "0":
            return
        try:
            if choice == "1":
                install_node(state, app)
            else:
                selected = choices.get(choice)
                if selected is not None:
                    node_card(selected, app)
        except _NodeGone:
            continue
        except Exception as exc:
            error(f"Операция не завершена ({type(exc).__name__}); проверь диагностику")


__all__ = ["menu_nodes", "node_card", "remove_node", "detach_node"]
