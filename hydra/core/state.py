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
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, TypeVar, get_type_hints
from hydra.core.state_migrations import (
    MIGRATIONS as _DEFAULT_MIGRATIONS,
    migrate_state,
    migrate_v0_to_v1,
    migrate_v1_to_v2,
    migrate_v2_to_v3,
    migrate_v3_to_v4,
    migrate_v4_to_v5,
    migrate_v5_to_v6,
    migrate_v6_to_v7,
    migrate_v7_to_v8,
    migrate_v8_to_v9,
)
from hydra.core.hydrabox_keys import generate_hydrabox_jwe_key
from hydra.core.state_runtime import (
    _RUNTIME_INSTALL_KEYS,
    desired_payload as _desired_payload,
    merge_runtime_state as _merge_runtime_state,
)
from hydra.core.state_models import (
    SCHEMA_VERSION,
    AppState,
    NetworkConfig,
    PluginState,
    TelegramConfig,
    UnsupportedStateVersion,
    User,
    add_user,
    find_user,
    get_protocol,
    validate_raw_state as _validate_raw_state,
    validate_state,
    validate_supported_version as _validate_supported_version,
)
from hydra.core.errors import StateConflictError

STATE_DIR = Path("/var/lib/hydra")
STATE_FILE = STATE_DIR / "state.json"


def _restrict_file(path: Path) -> None:
    """Restrict state/backup files to the current owner on POSIX systems.

    Windows does not expose POSIX mode bits in the same way; leaving the
    operation as a no-op there keeps the existing cross-platform test setup.
    """
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _fsync_directory(path: Path) -> None:
    """Persist the directory entry after an atomic replace on POSIX."""
    if os.name == "nt":
        return
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)

_lock = threading.Lock()
T = TypeVar("T")


@contextmanager
def _state_lock():
    """Serialize state access across both threads and HYDRA processes."""
    with _lock:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        lock_path = STATE_DIR / "state.lock"
        with lock_path.open("a+b") as lock_file:
            _restrict_file(lock_path)
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
        except Exception as exc:
            raise ValueError(f"could not resolve state type {cls.__name__}: {exc}") from exc
        kwargs = {}
        for key, value in data.items():
            field_type = resolved_types.get(key)
            if field_type is not None:
                # Older UI/config paths could persist null for boolean
                # switches. Treat null as omitted so the declared default is
                # used, while preserving an explicit false.
                if value is None and field_type is bool:
                    continue
                kwargs[key] = _from_dict(field_type, value)
        return cls(**kwargs)
    return data


def _read_raw_state_unlocked() -> dict:
    """Read and structurally validate the primary state or its backup."""
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        _validate_raw_state(raw)
        _validate_supported_version(raw)
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        backup = STATE_FILE.with_suffix(".json.bak")
        try:
            raw = json.loads(backup.read_text(encoding="utf-8"))
            _validate_raw_state(raw)
            _validate_supported_version(raw)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            quarantine = STATE_FILE.with_suffix(".json.corrupt")
            try:
                shutil.copy2(STATE_FILE, quarantine)
            except OSError:
                pass
            raise RuntimeError(
                f"State file is corrupt; recovery copy was saved to {quarantine}"
            ) from exc
    return raw


def _load_state_unlocked() -> AppState:
    if not STATE_FILE.exists():
        return AppState()
    raw = _read_raw_state_unlocked()

    version = raw.get("version", 0)
    if version < SCHEMA_VERSION:
        raw = _migrate(raw, version)
    _validate_raw_state(raw)
    return _from_dict(AppState, raw)


def load_state() -> AppState:
    """Загружает состояние из state.json. Создаёт пустое, если файла нет."""
    with _state_lock():
        return _load_state_unlocked()


def migrate_persisted_state() -> dict[str, int | bool]:
    """Atomically migrate an existing state file to the current schema."""
    with _state_lock():
        if not STATE_FILE.exists():
            return {
                "from": SCHEMA_VERSION,
                "to": SCHEMA_VERSION,
                "changed": False,
            }

        raw = _read_raw_state_unlocked()
        from_version = int(raw.get("version", 0))
        if from_version == SCHEMA_VERSION:
            return {
                "from": from_version,
                "to": SCHEMA_VERSION,
                "changed": False,
            }

        migrated = _migrate(raw, from_version)
        _validate_raw_state(migrated)
        state = _from_dict(AppState, migrated)
        for user in state.users:
            if not user.hydrabox_jwe_key:
                user.hydrabox_jwe_key = generate_hydrabox_jwe_key()
        _save_state_unlocked(state, current=copy.deepcopy(state))
        return {
            "from": from_version,
            "to": SCHEMA_VERSION,
            "changed": True,
        }


persist_state_migration = migrate_persisted_state


def _save_state_unlocked(
    state: AppState,
    *,
    current: AppState | None = None,
) -> None:
    for user in state.users:
        if not user.hydrabox_jwe_key:
            user.hydrabox_jwe_key = generate_hydrabox_jwe_key()
    if current is None:
        state.revision = max(1, int(state.revision))
    elif _desired_payload(state) != _desired_payload(current):
        if state.revision != current.revision:
            raise StateConflictError(
                "state changed since it was loaded; reload and retry",
            )
        state.revision = current.revision + 1
    else:
        state.revision = current.revision
    validate_state(state)
    data = _to_dict(state)
    if STATE_FILE.exists():
        backup = STATE_FILE.with_suffix(".json.bak")
        backup_pending = backup.with_suffix(".bak.pending")
        try:
            shutil.copy2(STATE_FILE, backup_pending)
            _restrict_file(backup_pending)
            backup_pending.replace(backup)
            _restrict_file(backup)
        finally:
            backup_pending.unlink(missing_ok=True)
    tmp = STATE_DIR / f"state.json.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_file(tmp)
        tmp.replace(STATE_FILE)
        _restrict_file(STATE_FILE)
        _fsync_directory(STATE_DIR)
    finally:
        tmp.unlink(missing_ok=True)


def save_state(state: AppState) -> None:
    """Сохраняет состояние в state.json (атомарно через temp-файл)."""
    with _state_lock():
        device_resets = set(state.install.pop("_device_binding_resets", []))
        latest = None
        if STATE_FILE.exists():
            latest = _load_state_unlocked()
            _merge_runtime_state(state, latest, device_resets)
        _save_state_unlocked(state, current=latest)


def restore_desired_state(snapshot: AppState) -> AppState:
    """Write a snapshot's desired configuration over the current state.

    A rollback must succeed even when a background writer advanced the
    revision meanwhile: the snapshot is the configuration that was already
    persisted, so it is restored against whatever is on disk now.
    """
    with _state_lock():
        restored = copy.deepcopy(snapshot)
        device_resets = set(restored.install.pop("_device_binding_resets", []))
        latest = _load_state_unlocked() if STATE_FILE.exists() else None
        if latest is not None:
            _merge_runtime_state(restored, latest, device_resets)
            restored.revision = latest.revision
        _save_state_unlocked(restored, current=latest)
        return restored


def update_state(mutator: Callable[[AppState], T]) -> tuple[AppState, T]:
    """Atomically load, mutate and save state under one process-wide lock."""
    with _state_lock():
        state = _load_state_unlocked()
        before = copy.deepcopy(state)
        result = mutator(state)
        _save_state_unlocked(state, current=before)
        return state, result


_migrate_v0_to_v1 = migrate_v0_to_v1
_migrate_v1_to_v2 = migrate_v1_to_v2
_migrate_v2_to_v3 = migrate_v2_to_v3
_migrate_v3_to_v4 = migrate_v3_to_v4
_MIGRATIONS = dict(_DEFAULT_MIGRATIONS)


def _migrate(data: dict, from_version: int) -> dict:
    """Compatibility facade over the pure ordered migration engine."""
    return migrate_state(
        data,
        from_version,
        migrations=_MIGRATIONS,
    )
