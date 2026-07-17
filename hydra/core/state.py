"""
hydra/core/state.py — Типизированное состояние приложения.

Все данные хранятся в /var/lib/hydra/state.json.
Поддерживается версионирование схемы и миграции между версиями.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import copy
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, TypeVar, get_type_hints

STATE_DIR = Path("/var/lib/hydra")
STATE_FILE = STATE_DIR / "state.json"
SCHEMA_VERSION = 2

_lock = threading.Lock()
T = TypeVar("T")


@contextmanager
def _state_lock():
    """Serialize state access across both threads and HYDRA processes."""
    with _lock:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        lock_path = STATE_DIR / "state.lock"
        with lock_path.open("a+b") as lock_file:
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                lock_file.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


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
    sub_domain: str = ""
    server_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)
    warp_enabled: bool = False
    dnscrypt_enabled: bool = False
    dnscrypt_port: int = 5300
    tproxy_enabled: bool = False
    tproxy_port: int = 1081   # порт dokodemo-door sing-box для TPROXY
    clash_api_enabled: bool = False
    clash_api_port: int = 9090
    clash_api_secret: str = ""


@dataclass
class SecurityConfig:
    """Настройки безопасности."""
    fail2ban_enabled: bool = False
    honeypot_enabled: bool = False
    ipban_enabled: bool = False


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
    origin = getattr(cls, "__origin__", None)
    if origin:
        if origin is list:
            item_cls = cls.__args__[0]
            return [_from_dict(item_cls, item) for item in data]
        if origin is dict:
            val_cls = cls.__args__[1]
            return {k: _from_dict(val_cls, v) for k, v in data.items()}
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


def _load_state_unlocked() -> AppState:
    if not STATE_FILE.exists():
        return AppState()
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        backup = STATE_FILE.with_suffix(".json.bak")
        try:
            raw = json.loads(backup.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            quarantine = STATE_FILE.with_suffix(".json.corrupt")
            try:
                shutil.copy2(STATE_FILE, quarantine)
            except OSError:
                pass
            raise RuntimeError(
                f"State file is corrupt; recovery copy was saved to {quarantine}"
            ) from exc

    version = raw.get("version", 0)
    if version < SCHEMA_VERSION:
        raw = _migrate(raw, version)
    return _from_dict(AppState, raw)


def load_state() -> AppState:
    """Загружает состояние из state.json. Создаёт пустое, если файла нет."""
    with _state_lock():
        return _load_state_unlocked()


def _save_state_unlocked(state: AppState) -> None:
    data = _to_dict(state)
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".json.bak"))
    tmp = STATE_DIR / f"state.json.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(STATE_FILE)
    finally:
        tmp.unlink(missing_ok=True)


def save_state(state: AppState) -> None:
    """Сохраняет состояние в state.json (атомарно через temp-файл)."""
    with _state_lock():
        # Long-running menus hold an older AppState while the traffic daemon
        # updates counters in another process. Preserve the monotonic runtime
        # accounting fields instead of letting an unrelated settings save roll
        # them back.
        if STATE_FILE.exists():
            latest = _load_state_unlocked()
            latest_users = {user.email: user for user in latest.users}
            for user in state.users:
                current = latest_users.get(user.email)
                if current is None:
                    continue
                user.traffic_used_bytes = max(
                    int(user.traffic_used_bytes), int(current.traffic_used_bytes),
                )
                for protocol, current_stats in current.credentials.items():
                    if not isinstance(current_stats, dict):
                        continue
                    target_stats = user.credentials.setdefault(protocol, {})
                    current_total = int(current_stats.get("traffic_used_bytes", 0))
                    target_total = int(target_stats.get("traffic_used_bytes", 0))
                    if current_total >= target_total:
                        target_stats["traffic_used_bytes"] = current_total
                        if "traffic_last_raw_bytes" in current_stats:
                            target_stats["traffic_last_raw_bytes"] = current_stats["traffic_last_raw_bytes"]
                        for stat_key, stat_value in current_stats.items():
                            if stat_key.startswith("traffic_") and stat_key not in {
                                "traffic_used_bytes", "traffic_last_raw_bytes",
                            }:
                                target_stats[stat_key] = copy.deepcopy(stat_value)
            for key in ("traffic_connection_counters", "traffic_log_cursors"):
                if key in latest.install:
                    state.install[key] = copy.deepcopy(latest.install[key])
        _save_state_unlocked(state)


def update_state(mutator: Callable[[AppState], T]) -> tuple[AppState, T]:
    """Atomically load, mutate and save state under one process-wide lock."""
    with _state_lock():
        state = _load_state_unlocked()
        result = mutator(state)
        _save_state_unlocked(state)
        return state, result


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
