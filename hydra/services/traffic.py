"""
hydra/services/traffic.py — Учёт трафика.

Агрегирует данные по трафику со всех плагинов и обновляет AppState.
"""
from __future__ import annotations

from hydra.core.state import AppState
from hydra.plugins.registry import get_all


def collect_traffic(state: AppState) -> dict[str, int]:
    """
    Собирает трафик со всех активных плагинов.
    Возвращает {email: total_bytes}.
    """
    traffic: dict[str, int] = {}

    for plugin in get_all():
        try:
            plugin_traffic = plugin.traffic()
            for email, bytes_used in plugin_traffic.items():
                traffic[email] = traffic.get(email, 0) + bytes_used
        except Exception:
            pass

    return traffic


def update_user_traffic(state: AppState) -> None:
    """
    Обновляет traffic_used_bytes для каждого пользователя
    на основе данных со всех плагинов.
    """
    total = collect_traffic(state)
    for user in state.users:
        if user.email in total:
            user.traffic_used_bytes = total[user.email]


def check_traffic_limits(state: AppState) -> list[str]:
    """
    Проверяет лимиты трафика и возвращает список email'ов,
    превысивших лимит.
    """
    update_user_traffic(state)
    exceeded: list[str] = []

    for user in state.users:
        if user.blocked:
            continue
        limit_bytes = int(user.traffic_limit_gb * 1073741824)  # GB → bytes
        if limit_bytes > 0 and user.traffic_used_bytes > limit_bytes:
            exceeded.append(user.email)

    return exceeded
