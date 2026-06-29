"""
hydra/plugins/base.py — Абстрактный интерфейс плагина.

Каждый протокол реализует этот интерфейс.
Плагин НЕ управляет своим жизненным циклом напрямую — он отдаёт фрагмент
Sing-Box конфига, а ядро собирает их в единый /etc/sing-box/config.json.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from hydra.core.state import AppState, PluginState


@dataclass
class PluginMeta:
    """Метаданные плагина."""
    name: str
    description: str
    version: str = "1.0.0"


@dataclass
class PluginStatus:
    """Статус плагина: установлен, активен, порт, доп. информация."""
    installed: bool
    enabled: bool
    running: bool
    port: int = 0
    info: dict = field(default_factory=dict)


@dataclass
class ConfigFragment:
    """Фрагмент конфига Sing-Box, который отдаёт плагин."""
    inbounds: list[dict] = field(default_factory=list)
    outbounds: list[dict] = field(default_factory=list)
    route_rules: list[dict] = field(default_factory=list)


class BasePlugin(ABC):
    """
    Базовый класс для всех плагинов протоколов.

    Порядок вызовов при жизни плагина:
      1. install()    — установка внешних зависимостей (бинарники, пакеты)
      2. configure()  — генерация Sing-Box конфига (вызывается при каждом изменении)
      3. status()     — проверка состояния
      4. traffic()    — сбор статистики
      5. uninstall()  — удаление
    """

    meta: PluginMeta

    @abstractmethod
    def install(self) -> bool:
        """
        Установка плагина: загрузка бинарников, Docker-образов, пакетов.
        Вызывается один раз при первом включении.
        Возвращает True при успехе.
        """
        ...

    @abstractmethod
    def uninstall(self) -> bool:
        """
        Удаление плагина: остановка служб, удаление файлов.
        Возвращает True при успехе.
        """
        ...

    @abstractmethod
    def configure(self, state: AppState) -> ConfigFragment:
        """
        Генерирует фрагмент конфига Sing-Box на основе текущего состояния.

        Вызывается при каждом изменении конфигурации любого плагина —
        все фрагменты собираются в единый /etc/sing-box/config.json,
        затем sing-box получает reload.
        """
        ...

    @abstractmethod
    def status(self) -> PluginStatus:
        """Возвращает статус плагина."""
        ...

    @abstractmethod
    def traffic(self) -> dict[str, int]:
        """
        Возвращает трафик в байтах по пользователям: {email: bytes}.
        Пустой словарь, если плагин не поддерживает учёт трафика.
        """
        ...

    # ── Необязательные методы ──────────────────────────────────────────────

    def menu_items(self, state: AppState) -> list[dict]:
        """
        Возвращает элементы меню для TUI:
          [{label: str, key: str, action: str, description: str}, ...]
        По умолчанию — базовый набор: включить/выключить, статус, трафик.
        """
        proto = state.protocols.get(self.meta.name)
        enabled = proto.enabled if proto else False
        return [
            {
                "label": f"{'✓' if enabled else '✗'} {self.meta.name}",
                "key": self.meta.name[0].upper(),
                "action": "toggle",
                "description": self.meta.description,
            },
        ]

    def on_enable(self, state: AppState) -> None:
        """Вызывается при включении плагина. Можно переопределить."""
        pass

    def on_disable(self, state: AppState) -> None:
        """Вызывается при отключении плагина. Можно переопределить."""
        pass
