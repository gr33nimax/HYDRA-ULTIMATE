"""
hydra/core/state.py — Типизированное состояние приложения.

Все данные хранятся в /var/lib/hydra/state.json.
Поддерживается версионирование схемы и миграции между версиями.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, get_type_hints

STATE_DIR = Path("/var/lib/hydra")
STATE_FILE = STATE_DIR / "state.json"
SCHEMA_VERSION = 2

_lock = threading.Lock()


# ═════════════════════════════════════════════════════════════════════════════
#  Модели данных
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class PluginState:
    """Состояние одного плагина (транспорт / надстройка / безопасность)."""
    enabled: bool = False
    port: int = 0
    installed: bool = False
    config: dict = field(default_factory=dict)


@dataclass
class User:
    """Учётная запись пользователя."""
    email: str
    uuid: str
    traffic_limit_gb: float = 0
    traffic_used_bytes: int = 0
    expiry_date: str = ""          # ISO-дата
    blocked: bool = False
    created_at: str = ""
    telegram_id: Optional[int] = None
    credentials: dict[str, dict] = field(default_factory=dict)
    # Per-user секреты по имени плагина.
    # Пример: user.credentials["mieru"] = {"username": "...", "password": "..."}


@dataclass
class TelegramConfig:
    """Конфигурация Telegram-ботов."""
    admin_token: str = ""
    admin_chat_id: str = ""
    bot_token: str = ""
    bot_enabled: bool = False
    admin_enabled: bool = False
    allowed_users: list[int] = field(default_factory=list)


@dataclass
class NetworkConfig:
    """Сетевые настройки."""
    domain: str = ""
    server_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)
    warp_enabled: bool = False
    dnscrypt_enabled: bool = False
    dnscrypt_port: int = 5300
    tproxy_enabled: bool = False
    tproxy_port: int = 1081   # порт dokodemo-door sing-box для TPROXY


@dataclass
class SecurityConfig:
    """Настройки безопасности."""
    geoip_block_enabled: bool = False
    geoip_port: int = 443
    fail2ban_enabled: bool = False
    honeypot_enabled: bool = False


@dataclass
class AppState:
    """Корневое состояние приложения."""
    version: int = SCHEMA_VERSION
    install: dict = field(default_factory=dict)            # install_mode, server_country, etc.
    protocols: dict[str, PluginState] = field(default_factory=dict)
    users: list[User] = field(default_factory=list)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


# ═════════════════════════════════════════════════════════════════════════════
#  Загрузка / сохранение
# ═════════════════════════════════════════════════════════════════════════════

def _to_dict(obj) -> dict:
    """Рекурсивно преобразует dataclass в словарь."""
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    return obj


def _from_dict(cls, data: dict):
    """Рекурсивно создаёт dataclass из словаря."""
    if cls is dict:
        return data
    if hasattr(cls, "__origin__") and cls.__origin__ is list:
        item_cls = cls.__args__[0]
        return [_from_dict(item_cls, item) for item in data]
    if hasattr(cls, "__dataclass_fields__"):
        # Разрешаем строковые аннотации (from __future__ import annotations)
        try:
            resolved_types = get_type_hints(cls)
        except Exception:
            resolved_types = {}
        kwargs = {}
        for key, value in data.items():
            field_type = resolved_types.get(key)
            if field_type is not None:
                kwargs[key] = _from_dict(field_type, value)
        return cls(**kwargs)
    return data


def load_state() -> AppState:
    """Загружает состояние из state.json. Создаёт пустое, если файла нет."""
    with _lock:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if not STATE_FILE.exists():
            return AppState()

        try:
            raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return AppState()

        version = raw.get("version", 0)
        if version < SCHEMA_VERSION:
            raw = _migrate(raw, version)

        return _from_dict(AppState, raw)


def save_state(state: AppState) -> None:
    """Сохраняет состояние в state.json (атомарно через temp-файл)."""
    with _lock:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        data = _to_dict(state)
        tmp = STATE_DIR / "state.json.tmp"
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding="utf-8")
        tmp.replace(STATE_FILE)


def _migrate(data: dict, from_version: int) -> dict:
    """Миграция схемы состояния между версиями."""
    # v0 → v1: нормализация структуры
    if from_version < 1:
        data.setdefault("version", 1)
        data.setdefault("install", data.get("install", {}))
        data.setdefault("protocols", data.get("protocols", {}))
        data.setdefault("telegram", data.get("telegram", {}))
        data.setdefault("network", data.get("network", {}))
        data.setdefault("security", data.get("security", {}))
    # v1 → v2: per-user credentials + tproxy
    if from_version < 2:
        for u in data.get("users", []):
            u.setdefault("credentials", {})
        net = data.setdefault("network", {})
        net.setdefault("tproxy_enabled", False)
        net.setdefault("tproxy_port", 1081)
        data["version"] = 2
    return data


# ═════════════════════════════════════════════════════════════════════════════
#  Удобные хелперы
# ═════════════════════════════════════════════════════════════════════════════

def get_protocol(state: AppState, name: str) -> PluginState:
    """Возвращает состояние протокола (создаёт, если нет)."""
    if name not in state.protocols:
        state.protocols[name] = PluginState()
    return state.protocols[name]


def find_user(state: AppState, email: str) -> Optional[User]:
    """Ищет пользователя по email."""
    for u in state.users:
        if u.email == email:
            return u
    return None


def add_user(state: AppState, user: User) -> None:
    """Добавляет пользователя. Заменяет существующего с тем же email."""
    existing = find_user(state, user.email)
    if existing:
        idx = state.users.index(existing)
        state.users[idx] = user
    else:
        state.users.append(user)
