"""The three endings of a managed node, each spelled out before anything happens.

Full removal deletes HYDRA from the VPS; withdrawal keeps the node managed but stops
serving users and profiles; detach only forgets the node on the base. They differ in
what happens to a working VPS, so they never share one confirmation screen, and every
one of them requires the operator to type the node's visible ID first.
"""

from __future__ import annotations

from hydra.core.state_nodes import NodeConfig
from hydra.services.application import ApplicationService
from hydra.ui.tui import ask, error, kv, menu, panel, success


def _exact_name(node: NodeConfig) -> str:
    return node.label


def typed_identity_matches(node: NodeConfig) -> bool:
    typed = ask(f"Введите точное «{_exact_name(node)}» для подтверждения")
    if typed is None:
        error("Отменено")
        return False
    if typed.strip() != _exact_name(node):
        error("Значение не совпало; операция отменена")
        return False
    return True


def numeric_confirm(question: str) -> bool:
    """A yes/no that cannot be answered by accident."""
    return menu([("1", "Выполнить", ""), ("0", "Отмена", "")], question) == "1"


def cleanup_warnings(result: dict[str, object]) -> list[str]:
    """Cleanup warnings the service actually produced, not whatever a mock returns."""
    found = result.get("cleanup_warnings")
    return [str(item) for item in found] if isinstance(found, list) else []


def remove_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "УДАЛЕНИЕ HYDRA С VPS",
        [
            kv("Нода:", node.label),
            kv("SSH:", f"{node.ssh_user}@{node.address}:{node.ssh_port}"),
            "Будут удалены принадлежащие HYDRA службы, программа и данные на ноде.",
            "Чужие службы, пользователи и ключи не затрагиваются.",
            "Локальная запись удаляется только после подтверждённой очистки по SSH.",
        ],
        wrap=True,
    )
    if not typed_identity_matches(node):
        return False
    if not numeric_confirm("Очистить HYDRA на этой VPS?"):
        return False
    result = app.nodes.remove_node(node.id, confirmed=True)
    success("Нода удалена")
    for warning in cleanup_warnings(result):
        error(f"Локальная очистка требует внимания: {warning}")
    return True


def withdraw_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "УБРАТЬ ИЗ ПОДПИСКИ",
        [
            kv("Нода:", node.label),
            "Выдача профилей прекращается, на ноде удаляются пользователи и протоколы.",
            "Управление и программа на VPS остаются: ноду можно настроить и вернуть.",
            "Следующая синхронизация не восстановит пользователей сама по себе.",
            "Уже учтённый трафик остаётся в общей квоте.",
        ],
        wrap=True,
    )
    if not typed_identity_matches(node):
        return False
    if not numeric_confirm("Убрать ноду из подписки и очистить пользователей на ноде?"):
        return False
    result = app.nodes.withdraw_node(node.id, confirmed=True)
    if result.get("remote_cleanup"):
        success("Нода убрана из подписки; пользователи и протоколы очищены на ноде")
    else:
        error("Из подписки убрана; очистка на ноде ожидает связи")
        detail = str(result.get("error_detail") or result.get("error") or "")
        if detail:
            error(f"Причина: {detail}")
    return True


def restore_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "ВЕРНУТЬ В ПОДПИСКУ",
        [
            kv("Нода:", node.label),
            "Нода снова получает текущих пользователей и настроенные протоколы.",
            "Ранее скачанные профили продолжат работать, но их лучше обновить.",
        ],
        wrap=True,
    )
    if not numeric_confirm("Вернуть ноду в подписку и синхронизировать?"):
        return False
    result = app.nodes.restore_node(node.id)
    success(f"Нода возвращена в подписку · {result.status}")
    return True


def detach_node(node: NodeConfig, app: ApplicationService) -> bool:
    panel(
        "ОТСОЕДИНЕНИЕ БЕЗ ОЧИСТКИ VPS",
        [
            kv("Нода:", node.label),
            "ВНИМАНИЕ: очистка НЕ выполняется.",
            "VPS и её службы продолжат работать, старые клиенты могут подключаться.",
            "На основе удаляются запись, публикация и credentials.",
            "Удалённо отозвать доступ без связи невозможно; очисти VPS отдельно.",
            "Уже учтённый трафик останется в общей квоте.",
        ],
        wrap=True,
    )
    if not typed_identity_matches(node):
        return False
    if not numeric_confirm("Отсоединить без остановки и удалённой очистки?"):
        return False
    result = app.nodes.detach_node(node.id, confirmed=True)
    success("Нода отсоединена от основы; удалённая VPS не очищена")
    for warning in cleanup_warnings(result):
        error(f"Локальная очистка требует внимания: {warning}")
    return True


__all__ = [
    "detach_node",
    "numeric_confirm",
    "remove_node",
    "restore_node",
    "typed_identity_matches",
    "withdraw_node",
]
