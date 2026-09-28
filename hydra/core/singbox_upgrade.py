"""Transactional Sing-Box binary upgrade with rollback."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from hydra.core.host import HOST
from hydra.core.singbox_config import migrate_legacy_default_dns
from hydra.utils.commands import redact_text


@dataclass(frozen=True)
class UpgradeOperations:
    """Runtime operations supplied by the Sing-Box compatibility facade."""

    find_binary: Callable[[], Path | None]
    is_running: Callable[[], bool]
    install: Callable[..., bool]
    get_version: Callable[[], str | None]
    run: Callable[..., Any]
    start: Callable[[], bool]
    stop: Callable[[], bool]
    log: Callable[[str, str], None]
    install_error: Callable[[], str] | None = None
    migrate_config: Callable[[Path], bool] | None = None


@dataclass(frozen=True)
class _ConfigMigration:
    backup: Path | None = None
    error: str = ""


def parse_version(value: str | None) -> tuple[int, ...]:
    """Parse every numeric release component for upgrade comparisons."""
    if not value:
        return (0,)
    parts = re.findall(r"\d+", value)
    try:
        return tuple(map(int, parts)) if parts else (0,)
    except ValueError:
        return (0,)


def newer_release_available(current: str | None, latest: str | None) -> bool:
    """Return true only when both versions are known and latest is newer."""
    return bool(current and latest and parse_version(latest) > parse_version(current))


# Capability gates were written against the legacy naming, which carried both the
# upstream baseline and a HydraCore cycle (`v1.14.0-extended-2.7.1-hydracore.12`).
# The readable contract names the baseline only (`hydracore-sbe-1.14.0`) and counts
# releases inside it, so a tag alone cannot say which cycle it belongs to. Both
# schemes are therefore mapped onto one rank: baseline components first, then the
# cycle. A release named by the readable contract comes from the line that carries
# these capabilities, so it ranks at that line and not below it.
#
# The leading `v` is optional: hydra.core.singbox.get_version() strips it from the
# token the core prints before anything compares versions.
_READABLE_CONTRACT_CYCLE = 10**6
_READABLE_CONTRACT_PATTERN = re.compile(r"hydracore-sbe-(\d+)\.(\d+)\.(\d+)")
_LEGACY_CORE_PATTERN = re.compile(r"v?(\d+)\.(\d+)\.(\d+)-extended(?:-\d+(?:\.\d+)*)?-hydracore\.(\d+)")

# The upstream Snell generations and the AWG 3.1 configuration fields both arrived
# with the sing-box-extended 1.14.0 line, HydraCore cycle 12.
MIN_UPSTREAM_CAPABILITY_CORE = (1, 14, 0, 12)
UPSTREAM_CAPABILITY_TEXT = "sing-box-extended 1.14.0"


def core_capability_rank(value: str | None) -> tuple[int, int, int, int] | None:
    """Rank a HydraCore version for gates written before the readable contract."""
    if not value:
        return None
    readable = _READABLE_CONTRACT_PATTERN.search(value)
    legacy = None if readable else _LEGACY_CORE_PATTERN.search(value)
    match = readable or legacy
    if match is None:
        return None
    cycle = _READABLE_CONTRACT_CYCLE if readable else None
    try:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        if cycle is None:
            cycle = int(match.group(4))
    except ValueError:
        return None
    return (major, minor, patch, cycle)


def core_supports_upstream_capability(version: str | None) -> bool:
    """Report whether a core version carries the upstream Snell/AWG 3.1 capability."""
    rank = core_capability_rank(version)
    return rank is not None and rank >= MIN_UPSTREAM_CAPABILITY_CORE


def _exception_text(exc: Exception) -> str:
    detail = str(exc).strip() or type(exc).__name__
    return redact_text(detail)


# The token a core prints is not always a bare number: under the readable tag
# contract it starts with a letter (`hydracore-sbe-1.14.0`), so a rule that only
# accepts a leading digit reads a perfectly good core as no version at all.
_READABLE_VERSION_TOKEN = re.compile(r"hydracore-sbe-\d+\.\d+\.\d+[0-9A-Za-z.+-]*")


def version_token(first_line: str) -> str | None:
    """Pick the version token out of a `sing-box version ...` line."""
    for token in first_line.split():
        candidate = token.removeprefix("v")
        if candidate[:1].isdigit() or _READABLE_VERSION_TOKEN.fullmatch(candidate):
            return candidate
    return None


def _result_detail(result: Any) -> str:
    output = str(getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return redact_text(output.splitlines()[-1]) if output else ""


def migrate_runtime_dns_config(config_path: Path) -> bool:
    """Atomically migrate HYDRA's legacy default DNS runtime artifact."""
    import json

    config = json.loads(config_path.read_text(encoding="utf-8"))
    migrated, changed = migrate_legacy_default_dns(config)
    if not changed:
        return False

    mode = config_path.stat().st_mode & 0o777
    HOST.atomic_write(
        config_path,
        json.dumps(migrated, indent=2, ensure_ascii=False) + "\n",
        mode=mode,
    )
    return True


def _restore_backup(backup: Path, target: Path, *, mode: int | None = None) -> None:
    pending = target.with_name(f".{target.name}.rollback")
    pending.unlink(missing_ok=True)
    try:
        shutil.copy2(backup, pending)
        if mode is not None:
            pending.chmod(mode)
        pending.replace(target)
    finally:
        pending.unlink(missing_ok=True)


def _remove_backup(
    backup: Path | None,
    operations: UpgradeOperations,
    *,
    label: str,
) -> None:
    if backup is None:
        return
    try:
        backup.unlink(missing_ok=True)
    except Exception as exc:
        operations.log("WARNING", f"Failed to remove {label} backup: {exc}")


def _prepare_config_migration(
    config_path: Path,
    operations: UpgradeOperations,
) -> _ConfigMigration:
    if not config_path.exists() or operations.migrate_config is None:
        return _ConfigMigration()

    backup = config_path.with_name(f"{config_path.name}.upgrade.bak")
    try:
        backup.unlink(missing_ok=True)
        shutil.copy2(config_path, backup)
    except Exception as exc:
        detail = _exception_text(exc)
        operations.log("ERROR", f"Failed to snapshot sing-box config: {detail}")
        return _ConfigMigration(error=f"Не удалось сохранить конфигурацию перед миграцией: {detail}")

    try:
        changed = operations.migrate_config(config_path)
    except Exception as exc:
        detail = _exception_text(exc)
        operations.log("ERROR", f"DNS config migration failed: {detail}")
        return _ConfigMigration(
            backup=backup,
            error=f"Не удалось мигрировать DNS-конфигурацию: {detail}",
        )

    if not changed:
        _remove_backup(backup, operations, label="unchanged config")
        return _ConfigMigration()

    operations.log("INFO", "Migrated legacy HYDRA DNS configuration")
    return _ConfigMigration(backup=backup)


def _rollback_upgrade(
    reason: str,
    *,
    target_binary: Path,
    backup_binary: Path,
    config_path: Path,
    config_backup: Path | None,
    was_running: bool,
    operations: UpgradeOperations,
) -> tuple[bool, str]:
    operations.log("ERROR", f"{reason}; rolling back to backup...")
    try:
        operations.stop()
    except Exception as exc:
        operations.log("WARNING", f"Failed to stop sing-box for rollback: {exc}")

    failures: list[str] = []
    try:
        _restore_backup(backup_binary, target_binary, mode=0o755)
    except Exception as exc:
        detail = _exception_text(exc)
        operations.log("CRITICAL", f"Binary rollback failed: {detail}")
        failures.append(f"старое ядро: {detail}")

    if config_backup is not None:
        try:
            _restore_backup(config_backup, config_path)
            _remove_backup(config_backup, operations, label="config")
        except Exception as exc:
            detail = _exception_text(exc)
            operations.log("CRITICAL", f"Config rollback failed: {detail}")
            failures.append(f"конфигурация: {detail}")

    if failures:
        return False, f"{reason}. Сбой восстановления: {'; '.join(failures)}"

    if was_running:
        try:
            restored = operations.start()
        except Exception as exc:
            restored = False
            operations.log("CRITICAL", f"Restored service start failed: {exc}")
        if not restored:
            operations.log(
                "CRITICAL",
                "Old binary and config were restored, but sing-box did not start",
            )
            return (
                False,
                f"{reason}. Старое ядро и конфигурация восстановлены, но служба не запустилась.",
            )
    return False, f"{reason}. Выполнен откат."


def upgrade_kernel(
    *,
    target_binary: Path,
    config_path: Path,
    operations: UpgradeOperations,
) -> tuple[bool, str]:
    """Replace the binary and restore the previous one on any failed check."""
    try:
        installed_binary = operations.find_binary()
    except Exception as exc:
        detail = _exception_text(exc)
        operations.log("ERROR", f"Failed to locate sing-box binary: {detail}")
        return False, f"Не удалось найти установленное ядро: {detail}"
    if installed_binary is None and target_binary.exists():
        installed_binary = target_binary
    if installed_binary is None:
        return False, "Sing-Box не установлен, обновление невозможно"

    try:
        was_running = operations.is_running()
    except Exception as exc:
        detail = _exception_text(exc)
        operations.log("ERROR", f"Failed to inspect sing-box status: {detail}")
        return False, f"Не удалось проверить состояние Sing-Box: {detail}"

    backup_binary = target_binary.with_suffix(".bak")
    config_migration = _ConfigMigration()
    operations.log(
        "INFO",
        f"Creating backup of sing-box binary to {backup_binary}",
    )
    try:
        backup_binary.unlink(missing_ok=True)
        shutil.copy2(installed_binary, backup_binary)
    except Exception as exc:
        operations.log("ERROR", f"Failed to create backup: {exc}")
        return False, f"Ошибка создания резервной копии: {exc}"

    def rollback(reason: str) -> tuple[bool, str]:
        return _rollback_upgrade(
            reason,
            target_binary=target_binary,
            backup_binary=backup_binary,
            config_path=config_path,
            config_backup=config_migration.backup,
            was_running=was_running,
            operations=operations,
        )

    install_detail = ""
    try:
        installed = operations.install(force=True)
    except Exception as exc:
        install_detail = _exception_text(exc)
        operations.log(
            "ERROR",
            f"Installation failed during update: {install_detail}",
        )
        installed = False
    if not installed:
        if not install_detail and operations.install_error is not None:
            try:
                install_detail = redact_text(operations.install_error().strip())
            except Exception as exc:
                operations.log(
                    "WARNING",
                    f"Failed to read installation error: {_exception_text(exc)}",
                )
        reason = "Не удалось скачать или распаковать обновление"
        if install_detail:
            reason = f"{reason}: {install_detail}"
        return rollback(reason)

    try:
        new_version = operations.get_version()
    except Exception as exc:
        return rollback(
            f"Не удалось проверить новый бинарник: {_exception_text(exc)}",
        )
    if not new_version:
        return rollback("Новый бинарник не запускается")

    config_migration = _prepare_config_migration(config_path, operations)
    if config_migration.error:
        return rollback(config_migration.error)

    if config_path.exists():
        try:
            result = operations.run(
                [str(target_binary), "check", "-c", str(config_path)],
            )
        except Exception as exc:
            return rollback(
                f"Не удалось проверить конфигурацию новым ядром: {_exception_text(exc)}",
            )
        if result.returncode != 0:
            detail = _result_detail(result)
            operations.log(
                "ERROR",
                f"New binary rejected existing config, rolling back. Detail: {detail or 'unknown error'}",
            )
            reason = "Конфигурация несовместима с новым ядром"
            if detail:
                reason = f"{reason}: {detail}"
            return rollback(reason)

    if was_running:
        operations.log("INFO", "Restarting service and checking status...")
        try:
            started = operations.start()
        except Exception as exc:
            return rollback(
                f"Служба не смогла запуститься с новым ядром: {_exception_text(exc)}",
            )
        if not started:
            return rollback(
                "Служба не смогла запуститься с новым ядром",
            )

    _remove_backup(config_migration.backup, operations, label="config")
    _remove_backup(backup_binary, operations, label="binary")

    _clear_update_flags(operations.log)
    return True, f"Ядро успешно обновлено до версии {new_version}"


def _clear_update_flags(log: Callable[[str, str], None]) -> None:
    try:
        from hydra.core.state import update_state

        def reset_update_flag(state) -> bool:
            state.install.pop("singbox_update_available", None)
            state.install.pop("singbox_latest_version", None)
            return True

        update_state(reset_update_flag)
    except Exception as exc:
        log("WARNING", f"Failed to reset update flags in state: {exc}")


__all__ = [
    "UpgradeOperations",
    "migrate_runtime_dns_config",
    "newer_release_available",
    "parse_version",
    "upgrade_kernel",
]
