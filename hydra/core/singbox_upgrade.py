"""Transactional Sing-Box binary upgrade with rollback."""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

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


def parse_version(value: str | None) -> tuple[int, ...]:
    """Parse every numeric release component for upgrade comparisons."""
    if not value:
        return (0,)
    parts = re.findall(r"\d+", value)
    try:
        return tuple(map(int, parts)) if parts else (0,)
    except ValueError:
        return (0,)


def _exception_text(exc: Exception) -> str:
    detail = str(exc).strip() or type(exc).__name__
    return redact_text(detail)


def _result_detail(result: Any) -> str:
    output = str(
        getattr(result, "stderr", "")
        or getattr(result, "stdout", "")
        or ""
    ).strip()
    return redact_text(output.splitlines()[-1]) if output else ""


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
        operations.log("ERROR", f"{reason}; rolling back to backup...")
        try:
            operations.stop()
        except Exception:
            pass
        try:
            target_binary.unlink(missing_ok=True)
            shutil.copy2(backup_binary, target_binary)
            target_binary.chmod(0o755)
        except Exception as exc:
            operations.log("CRITICAL", f"Rollback failed: {exc}")
            return (
                False,
                f"{reason}. Сбой восстановления старого ядра: {exc}",
            )

        if was_running:
            try:
                restored = operations.start()
            except Exception as exc:
                restored = False
                operations.log(
                    "CRITICAL",
                    f"Restored service start failed: {exc}",
                )
            if not restored:
                operations.log(
                    "CRITICAL",
                    "Old binary was restored, but sing-box did not start",
                )
                return (
                    False,
                    f"{reason}. Старое ядро восстановлено, "
                    "но служба не запустилась.",
                )
        return False, f"{reason}. Выполнен откат."

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

    if config_path.exists():
        try:
            result = operations.run(
                [str(target_binary), "check", "-c", str(config_path)],
            )
        except Exception as exc:
            return rollback(
                "Не удалось проверить конфигурацию новым ядром: "
                f"{_exception_text(exc)}",
            )
        if result.returncode != 0:
            detail = _result_detail(result)
            operations.log(
                "ERROR",
                "New binary rejected existing config, rolling back. "
                f"Detail: {detail or 'unknown error'}",
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
                "Служба не смогла запуститься с новым ядром: "
                f"{_exception_text(exc)}",
            )
        if not started:
            return rollback(
                "Служба не смогла запуститься с новым ядром",
            )

    try:
        backup_binary.unlink(missing_ok=True)
    except Exception as exc:
        operations.log(
            "WARNING",
            f"Failed to remove backup file: {exc}",
        )

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


__all__ = ["UpgradeOperations", "parse_version", "upgrade_kernel"]
