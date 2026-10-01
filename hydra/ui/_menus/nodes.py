"""Base-side node management: the operator's scenario, no direct host access.

The screen answers three questions in order: what nodes exist, is each of them fine,
and what do I do about the one I opened. Numbers are stable — 1 is always the first
action of the screen, 5 is always removal on a node card — so the operator never has
to re-read the list to find something again.

Every effect goes through ApplicationService ports; this module renders, asks and
reports, and never talks to SSH, the firewall, the state file or a subprocess itself.
"""

from __future__ import annotations

from typing import Any

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.application import ApplicationService
from hydra.services.nodes.observation import NodeObservation
from hydra.services.nodes.status import summary_line
from hydra.ui._menus.node_cookies import calls_cookies_prompt, import_vk_cookies
from hydra.ui._menus.node_details import (
    STAGE_LABELS,
    checked_at_text,
    connection_row,
    coverage_row,
    level_text,
    list_lines,
    publication_row,
    reason_row,
    short_revision,
    status_of_node,
    upgrade_row,
)
from hydra.ui._menus.node_removal import (
    detach_node,
    remove_node,
    restore_node,
    withdraw_node,
)
from hydra.ui._menus.nodes_setup import install_node, protocol_choices, read_protocol, resolve_revision
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import ask, clear, confirm, error, kv, menu, panel, prompt, success

# Kept as module attributes for compatibility with the helpers' old import sites.
_publication_row = publication_row
_connection_row = connection_row
_reason_row = reason_row
_coverage_row = coverage_row
_upgrade_row = upgrade_row
_list_lines = list_lines
_calls_cookies_prompt = calls_cookies_prompt
_import_vk_cookies = import_vk_cookies


class _NodeGone(Exception):
    """Signals that the node no longer exists, so its card must close."""


def _string_list(value: object) -> list[str]:
    """Only a real list of strings is a report; a mock must not be iterated."""
    return [str(item) for item in value] if isinstance(value, list) else []


def _observations(app: ApplicationService) -> dict[str, NodeObservation]:
    """Last known runtime state per node; an unavailable store reads as none."""
    try:
        found = app.nodes.observations()
    except Exception:
        return {}
    return found if isinstance(found, dict) else {}


# ── node card ───────────────────────────────────────────────────────────────


def node_card(node: NodeConfig, app: ApplicationService) -> None:
    while True:
        state = app.admin.load_state()
        current = next((item for item in app.nodes.list_nodes(state) if item.id == node.id), None)
        if current is None:
            return
        node = current
        observation = _observations(app).get(node.id)
        status = status_of_node(node, observation)
        reason = reason_row(observation) or status.reason
        clear()
        panel(
            "НОДА",
            [
                kv("ID:", node.display_id or node.id),
                kv("Имя:", node.name or node.id),
                kv("Адрес:", node.address),
                kv("SSH:", f"{node.ssh_user}@{node.address}:{node.ssh_port}"),
                kv("Статус:", level_text(status)),
                kv("Проверена:", checked_at_text(status)),
                kv("Связь:", connection_row(observation)),
                kv("Подписки:", coverage_row(node, observation)),
                kv("Обновление:", upgrade_row(node, observation)),
                *([kv("Причина:", reason)] if reason else []),
                "Офлайн-блокировки и общие квоты применяются после связи с нодой.",
            ],
            wrap=True,
        )
        choice = menu(
            [
                ("1", "Настройки протоколов", "публичные параметры; после сохранения — синхронизация"),
                ("2", "Внешний вид", "ID и имя; техническая привязка не меняется"),
                ("3", "Синхронизировать", "трафик, блокировки, применение, подписки"),
                ("4", "Обновление", "установка версии с отчётом"),
                ("5", "Удаление", "полная очистка, вывод из подписки или отсоединение"),
                ("0", "Назад", ""),
            ],
            "УПРАВЛЕНИЕ НОДОЙ",
        )
        try:
            if choice == "0":
                return
            if choice == "1":
                _protocols(node, app)
            elif choice == "2":
                _appearance(node, app)
            elif choice == "3":
                _sync(node, app)
            elif choice == "4":
                _upgrade(node, app)
            elif choice == "5":
                _deletion(node, app)
        except _NodeGone:
            return
        except Exception as exc:
            error(f"Операция не выполнена: {exc if str(exc) else type(exc).__name__}")


# ── appearance ──────────────────────────────────────────────────────────────


def _appearance(node: NodeConfig, app: ApplicationService) -> None:
    """Rename what the operator sees; trust, exports and accounting stay untouched."""
    choice = menu(
        [
            ("1", "Видимый ID", node.label),
            ("2", "Имя", node.name or node.id),
            ("0", "Назад", ""),
        ],
        "ВНЕШНИЙ ВИД",
    )
    if choice == "1":
        value = ask("Новый видимый ID (пусто — оставить)", node.display_id)
        if value is None or value == node.display_id:
            return
        try:
            app.nodes.set_appearance(node.id, display_id=value)
        except Exception as exc:
            error(f"ID не сохранён: {exc}")
            return
        success("Видимый ID сохранён; сертификаты, ключи и учёт трафика не менялись")
    elif choice == "2":
        value = ask("Новое имя (пусто — оставить)", node.name)
        if value is None or value == node.name:
            return
        try:
            app.nodes.set_appearance(node.id, name=value)
        except Exception as exc:
            error(f"Имя не сохранено: {exc}")
            return
        success("Имя сохранено")


# ── protocols ───────────────────────────────────────────────────────────────


def _protocol_diff(before: NodeProtocolSpec | None, after: NodeProtocolSpec) -> list[str]:
    """Show exactly what changes, so a save is never a blind overwrite."""
    lines: list[str] = []
    old_enabled = before.enabled if before is not None else None
    if old_enabled != after.enabled:
        lines.append(f"включение: {'включён' if after.enabled else 'выключен'}")
    old_config = dict(before.config) if before is not None else {}
    for key in sorted(set(old_config) | set(after.config)):
        old, new = old_config.get(key), after.config.get(key)
        if old != new:
            lines.append(f"{key}: {old if old is not None else '—'} → {new if new is not None else '—'}")
    if before is not None and before.port != after.port:
        lines.append(f"порт: {before.port} → {after.port}")
    return lines


def _protocols(node: NodeConfig, app: ApplicationService) -> None:
    """Configure one transport at a time, then run the shared full sync."""
    while True:
        choices = {str(index): name for index, name in enumerate(sorted(node.protocols), 1)}
        add_key = str(len(choices) + 1)
        labels = dict(protocol_choices(app).values())
        options = [
            (
                key,
                labels.get(name, protocol_label(name)),
                "включён" if node.protocols[name].enabled else "выключен",
            )
            for key, name in choices.items()
        ]
        options.extend(
            [
                (add_key, "Добавить протокол", "выбрать из поддерживаемых"),
                ("0", "Назад", ""),
            ]
        )
        choice = menu(options, "ПРОТОКОЛЫ НОДЫ")
        if choice == "0":
            return
        if choice == add_key:
            available = protocol_choices(app)
            selected = available.get(
                menu(
                    [(key, label, "") for key, (_, label) in available.items()] + [("0", "Назад", "")],
                    "ДОБАВИТЬ ПРОТОКОЛ",
                )
            )
            name = selected[0] if selected is not None else None
        else:
            name = choices.get(choice)
        if name is None:
            continue
        if name == "calls" and calls_cookies_prompt(node, app):
            continue
        if _protocol_menu(node, app, name) == "saved":
            return


def _protocol_menu(node: NodeConfig, app: ApplicationService, name: str) -> str:
    """One transport's own screen: parameters or the name users see in the list."""
    label = protocol_label(name)
    action = menu(
        [
            ("1", "Настроить параметры", "публичные настройки протокола"),
            ("2", "Имя профиля в подписке", "работает офлайн"),
            ("0", "Назад", ""),
        ],
        label,
    )
    if action == "2":
        _profile_name(node, app, name)
        return "renamed"
    if action != "1":
        return "back"
    before = node.protocols.get(name)
    spec = read_protocol(name, app, before or NodeProtocolSpec())
    if spec is None:
        return "back"
    diff = _protocol_diff(before, spec)
    if diff:
        panel("ИЗМЕНЕНИЯ", [f"{label}: {line}" for line in diff], wrap=True)
    else:
        success("Параметры не изменились")
        return "back"
    if not confirm("Сохранить и синхронизировать ноду?", default=False):
        return "back"
    result = app.nodes.save_protocol(node.id, name, spec)
    if result.get("applied"):
        success(f"Сохранено и применено · {result.get('status')}")
        for warning in _string_list(result.get("warnings")):
            error(f"Предупреждение: {warning}")
    else:
        error(f"Сохранено, ожидает применения: {result.get('detail') or result.get('error')}")
    return "saved"


def _profile_name(node: NodeConfig, app: ApplicationService, protocol: str) -> None:
    """Rename one profile in the subscription; this never needs the node."""
    keys = {key for key in node.profile_names if key == protocol or key.startswith(f"{protocol}:")}
    keys.add(protocol)
    state = app.admin.load_state()
    export = app.nodes.published_export(state, node.id)
    if export is not None:
        for user in export.users.values():
            for profile in user.profiles:
                if profile.protocol != protocol:
                    continue
                keys.add(f"{profile.protocol}:{profile.profile}" if profile.profile else profile.protocol)
    choices = {str(index): key for index, key in enumerate(sorted(keys), 1)}
    options = [(number, key, node.profile_names.get(key, "")) for number, key in choices.items()]
    options.append(("0", "Назад", ""))
    key = choices.get(menu(options, "ИМЯ ПРОФИЛЯ НОДЫ"))
    if key is None:
        return
    value = ask("Новое имя; - убирает override", node.profile_names.get(key, ""))
    if value is None:
        return
    app.nodes.change_profile_name(node.id, key, "" if value == "-" else value)
    success("Имя сохранено на основе; связь с нодой не требуется")


# ── sync ────────────────────────────────────────────────────────────────────


def _sync(node: NodeConfig, app: ApplicationService) -> None:
    """Run the shared full cycle now instead of waiting for the five-minute timer."""
    clear()
    panel(
        "СИНХРОНИЗАЦИЯ",
        [
            kv("Нода:", node.label),
            "Сейчас: опрос состояния и трафика, учёт квот и блокировок,",
            "применение настроек и обновление профилей в подписках.",
        ],
        wrap=True,
    )
    ok, message = app.admin.run_sync_agent()
    if ok:
        success("Синхронизация выполнена")
    else:
        error(f"Синхронизация завершилась неполно: {message}")
    _sync_report(node, app)


def _sync_report(node: NodeConfig, app: ApplicationService) -> None:
    state = app.admin.load_state()
    current = next((item for item in app.nodes.list_nodes(state) if item.id == node.id), None)
    if current is None:
        return
    observation = _observations(app).get(node.id)
    status = status_of_node(current, observation)
    reason = reason_row(observation) or status.reason
    panel(
        "ОТЧЁТ О СИНХРОНИЗАЦИИ",
        [
            kv("Статус:", level_text(status)),
            kv("Связь:", connection_row(observation)),
            kv("Подписки:", coverage_row(current, observation)),
            kv("Обновление:", upgrade_row(current, observation)),
            *([kv("Причина:", reason)] if reason else []),
        ],
        wrap=True,
    )
    prompt("Нажмите Enter")


# ── update ──────────────────────────────────────────────────────────────────


def _upgrade(node: NodeConfig, app: ApplicationService) -> None:
    branch = ask("Ветка (0 — отмена)", node.branch)
    if branch in (None, "0"):
        return
    revision = resolve_revision(app, branch)
    if revision is None:
        return
    observation = _observations(app).get(node.id)
    panel(
        "ПЛАН ОБНОВЛЕНИЯ НОДЫ",
        [
            kv("Нода:", node.label),
            kv("Ветка:", branch),
            kv("SHA (получен автоматически):", revision),
            kv(
                "Установлено:",
                short_revision(str(getattr(observation, "installed_revision", "") or "")) or "неизвестно",
            ),
        ],
        wrap=True,
    )
    if not confirm(f"Запланировать обновление {node.label} до {revision}?", default=False):
        return
    app.nodes.change_update_target(node.id, branch=branch, revision=revision)
    result = app.nodes.update(node.id)
    if result.get("already_scheduled"):
        error("Обновление уже было запланировано; второй запуск не потребовался")
        return
    success("Обновление запланировано")
    panel(
        "ОТЧЁТ ОБ ОБНОВЛЕНИИ",
        [
            kv("Цель:", revision),
            "Запланирование — не завершение: карточка покажет установленную",
            "версию и публикацию профилей после реального обновления.",
        ],
        wrap=True,
    )
    prompt("Нажмите Enter")


# ── removal ─────────────────────────────────────────────────────────────────


def _deletion(node: NodeConfig, app: ApplicationService) -> None:
    """Three different endings, each spelled out before anything happens."""
    if node.withdrawn:
        choice = menu(
            [
                ("1", "Вернуть в подписку", "снова выдавать профили пользователям"),
                ("2", "Удалить HYDRA с VPS", "полная очистка принадлежащей HYDRA установки"),
                ("3", "Отсоединить", "очистки нет, VPS продолжит работать"),
                ("0", "Назад", ""),
            ],
            "УДАЛЕНИЕ И ВЫВОД",
        )
        if choice == "1" and restore_node(node, app):
            return
        if choice == "2" and remove_node(node, app):
            raise _NodeGone
        if choice == "3" and detach_node(node, app):
            raise _NodeGone
        return
    choice = menu(
        [
            ("1", "Удалить HYDRA с VPS", "полная очистка принадлежащей HYDRA установки"),
            ("2", "Убрать из подписки", "на ноде удаляются пользователи и протоколы"),
            ("3", "Отсоединить", "очистки нет, VPS продолжит работать"),
            ("0", "Назад", ""),
        ],
        "УДАЛЕНИЕ И ВЫВОД",
    )
    if choice == "1" and remove_node(node, app):
        raise _NodeGone
    if choice == "2" and withdraw_node(node, app):
        return
    if choice == "3" and detach_node(node, app):
        raise _NodeGone


# ── list ────────────────────────────────────────────────────────────────────


def menu_nodes(state: AppState, app: ApplicationService) -> None:
    del state
    while True:
        state = app.admin.load_state()
        listed = app.nodes.list_nodes(state)
        observations = _observations(app)
        choices = {str(index): item for index, item in enumerate(listed, 2)}
        options: list[tuple[str, str, Any]] = [("1", "Установить", "SSH, протоколы, проверка перед установкой")]
        for key, item in choices.items():
            title = f"{item.label} · {item.name}" if item.name and item.name != item.label else item.label
            options.append((key, title, list_lines(item, observations.get(item.id))))
        options.append(("0", "Назад", ""))
        clear()
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
            error(f"Операция не завершена: {exc if str(exc) else type(exc).__name__}")


__all__ = [
    "STAGE_LABELS",
    "detach_node",
    "menu_nodes",
    "node_card",
    "remove_node",
    "restore_node",
    "withdraw_node",
]
