"""State machine for automatic Telemt Middle Proxy fallback."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread

from hydra.plugins.telemt.telemt_fallback_model import FallbackConfig
from hydra.plugins.telemt.telemt_fallback_probe import MiddleProxyProbe


@dataclass(frozen=True)
class FallbackOperations:
    """Side effects consumed by the fallback state machine."""

    journal_failures: Callable[[], list[str]]
    patch_mode: Callable[[Path, bool], bool]
    reload_service: Callable[[str], bool]
    read_runtime_mode: Callable[[Path], bool | None]
    log: Callable[[str, str], None]
    quorum: Callable[[], float]


class FallbackOrchestrator:
    """Coordinate probing, fallback, reload, and optional automatic recovery."""

    def __init__(
        self,
        fb_config: FallbackConfig,
        config_file: Path,
        service: str,
        probe: MiddleProxyProbe,
        operations: FallbackOperations,
        on_fallback: Callable[[str], None] | None = None,
        *,
        event_factory: Callable[[], Event] = Event,
        thread_factory: Callable[..., Thread] = Thread,
    ) -> None:
        self._fb = fb_config
        self._cfg_file = config_file
        self._service = service
        self._probe = probe
        self._operations = operations
        self._on_fallback = on_fallback
        self._mode = "middle"
        self._attempts = 0
        self._stop_event = event_factory()
        self._thread_factory = thread_factory
        self._watchdog_thread: Thread | None = None

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def fallback_active(self) -> bool:
        return self._mode == "direct"

    def status(self) -> dict[str, object]:
        return {
            "mode": self._mode,
            "attempts": self._attempts,
            "fallback_active": self.fallback_active,
            "fb_config": self._fb,
        }

    def run_with_fallback(self) -> str:
        if not self._fb.fallback_to_direct:
            self._mode = "middle"
            return (
                "Fallback отключён (fallback_to_direct=false) — "
                "оставляем Middle Proxy"
            )

        journal_hits = self._operations.journal_failures()
        if journal_hits:
            self._operations.log(
                "Обнаружены признаки отказа ME в логах "
                f"({len(journal_hits)} совпадений):",
                "WARN",
            )
            for hit in journal_hits[:3]:
                self._operations.log(f"  → {hit}", "WARN")

        deadline = time.monotonic() + self._fb.fallback_after_seconds
        available = False
        for attempt in range(1, self._fb.fallback_after_attempts + 1):
            self._attempts = attempt
            if self._stop_event.is_set():
                break
            if time.monotonic() > deadline:
                self._operations.log(
                    "WARN  Middle Proxy warmup timeout exceeded "
                    f"({self._fb.fallback_after_seconds}s)",
                    "WARN",
                )
                break

            self._operations.log(
                "Проба ME-серверов "
                f"(попытка {attempt}/{self._fb.fallback_after_attempts})...",
                "INFO",
            )
            ok, total = self._probe.probe_all()
            ratio = ok / total if total else 0
            quorum = self._operations.quorum()
            if ratio >= quorum:
                self._operations.log(
                    f"ME-пул доступен: {ok}/{total} endpoint'ов активны",
                    "OK",
                )
                available = True
                break
            self._operations.log(
                "WARN  ME pool initialization failed after attempt "
                f"{attempt} ({ok}/{total} endpoint'ов, кворум {quorum:.0%})",
                "WARN",
            )
            if attempt < self._fb.fallback_after_attempts:
                wait = min(
                    10,
                    self._fb.fallback_after_seconds
                    // self._fb.fallback_after_attempts,
                )
                self._stop_event.wait(timeout=wait)

        if available and not journal_hits:
            self._mode = "middle"
            return (
                "Middle Proxy инициализирован успешно — "
                "продолжаем в режиме Middle Proxy"
            )
        reason = (
            f"ME pool initialization failed after {self._attempts} attempts"
            if not available
            else "Обнаружены сигналы отказа ME в журнале"
        )
        return self._do_fallback(reason)

    def _do_fallback(self, reason: str) -> str:
        self._operations.log(
            "WARN  ME pool initialization failed for too long → "
            "falling back to Direct DC mode for stability",
            "WARN",
        )
        self._operations.log(f"  Причина: {reason}", "WARN")

        patched = self._operations.patch_mode(self._cfg_file, False)
        if patched:
            if not self._operations.reload_service(self._service):
                self._operations.log(
                    "systemctl reload вернул ненулевой код — изменения "
                    "применятся при следующем рестарте",
                    "WARN",
                )
            else:
                self._operations.log(
                    "INFO  Runtime transport mode switched: "
                    "Middle Proxy -> Direct",
                    "INFO",
                )
        else:
            self._operations.log(
                "Не удалось обновить telemt.toml — конфиг не изменён",
                "ERROR",
            )

        self._mode = "direct"
        if self._on_fallback:
            try:
                self._on_fallback(reason)
            except Exception:
                pass
        return (
            "Fallback выполнен: Middle Proxy → Direct Mode "
            f"(причина: {reason})"
        )

    def apply_reload_config(
        self,
        new_fb: FallbackConfig | None = None,
    ) -> str:
        if new_fb is not None:
            self._fb = new_fb
            self._fb.__post_init__()

        want_middle = self._operations.read_runtime_mode(self._cfg_file)
        self._operations.log(
            "INFO  Configuration reload: "
            f"use_middle_proxy={want_middle}, current_mode={self._mode}",
            "INFO",
        )
        if want_middle is True:
            self._operations.log(
                "INFO  Configuration reload requested Middle Proxy mode, "
                "starting ME pool initialization",
                "INFO",
            )
            self._attempts = 0
            self._stop_event.clear()
            if self._mode == "direct":
                self._operations.patch_mode(self._cfg_file, True)
                self._operations.reload_service(self._service)
                self._mode = "middle"
            return self.run_with_fallback()

        if want_middle is False:
            self._mode = "direct"
            self._operations.patch_mode(self._cfg_file, False)
            self._operations.reload_service(self._service)
            return "Reload: конфиг требует Direct Mode — применено"

        return (
            "Reload: use_middle_proxy не найден в конфиге — "
            "состояние не изменено"
        )

    def start_auto_revert_watchdog(self, check_interval: int = 120) -> None:
        if not self._fb.auto_revert_to_middle:
            return
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return

        def watchdog() -> None:
            consecutive_ok = 0
            self._operations.log(
                "INFO  Auto-revert watchdog started "
                f"(interval={check_interval}s, hysteresis=3 consecutive OK)",
                "INFO",
            )
            while not self._stop_event.wait(timeout=check_interval):
                if self._mode != "direct":
                    consecutive_ok = 0
                    continue
                ok, total = self._probe.probe_all()
                ratio = ok / total if total else 0
                if ratio >= self._operations.quorum():
                    consecutive_ok += 1
                    self._operations.log(
                        "INFO  Auto-revert: ME-серверы доступны "
                        f"({ok}/{total}), consecutive_ok={consecutive_ok}/3",
                        "INFO",
                    )
                    if consecutive_ok >= 3:
                        self._operations.log(
                            "INFO  Auto-revert: кворум стабилен 3 раза "
                            "подряд — возвращаем Middle Proxy",
                            "INFO",
                        )
                        self._attempts = 0
                        result = self.apply_reload_config()
                        self._operations.log(
                            f"Auto-revert result: {result}",
                            "INFO",
                        )
                        consecutive_ok = 0
                else:
                    if consecutive_ok:
                        self._operations.log(
                            "INFO  Auto-revert: ME-серверы снова "
                            f"недоступны ({ok}/{total}) — сброс счётчика",
                            "INFO",
                        )
                    consecutive_ok = 0

        self._watchdog_thread = self._thread_factory(
            target=watchdog,
            daemon=True,
            name="telemt-auto-revert",
        )
        self._watchdog_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=5)


def run_post_install_check(
    config_file: Path,
    service: str,
    warmup_wait: int,
    *,
    read_config: Callable[[Path], FallbackConfig],
    read_runtime_mode: Callable[[Path], bool | None],
    orchestrator_factory: Callable[..., FallbackOrchestrator],
    sleep: Callable[[float], None],
    log: Callable[[str, str], None],
) -> str | None:
    """Run the post-install check using dependencies supplied by the facade."""

    fallback = read_config(config_file)
    want_middle = read_runtime_mode(config_file)
    if not want_middle or not fallback.fallback_to_direct:
        return None

    log(
        f"Ожидаю {warmup_wait}с прогрева Middle Proxy перед пробой...",
        "INFO",
    )
    sleep(warmup_wait)
    orchestrator = orchestrator_factory(
        fb_config=fallback,
        config_file=config_file,
        service=service,
    )
    result = orchestrator.run_with_fallback()
    log(result, "INFO")
    if orchestrator.fallback_active:
        orchestrator.start_auto_revert_watchdog()
        return result
    return None
