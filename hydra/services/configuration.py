"""Transactional configuration apply pipeline."""
from __future__ import annotations

import copy
import shutil
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable

from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.state_models import AppState


@dataclass(frozen=True)
class ConfigurationApplier:
    """Apply generated config, host networking and plugin runtime atomically."""

    registry: Any
    singbox: Any
    nft: Any
    save_state: Callable[[AppState], None]
    set_apply_error: Callable[[str], None]
    last_apply_error: Callable[[], str]
    journal: Callable[..., None]
    manage_traffic_daemon: Callable[[AppState], None]
    migrate_haproxy: Callable[[AppState], None]

    def apply(self, state: AppState) -> bool:
        self.set_apply_error("")
        self.journal("started")
        transaction = ApplyTransaction()

        def fail(
            stage: str,
            message: str,
            *,
            reload_restored: bool = False,
        ) -> bool:
            self.set_apply_error(message)
            self.singbox.log("ERROR", message)
            transaction.rollback(
                lambda error: self.singbox.log("ERROR", error),
            )
            self.journal("rolled_back", stage=stage, error=message)
            if reload_restored:
                try:
                    self.singbox.reload()
                except Exception as exc:
                    self.singbox.log(
                        "ERROR",
                        f"Не удалось перезагрузить восстановленный Sing-Box: {exc}",
                    )
            return False

        if not state.network.tproxy_enabled:
            state.network.tproxy_enabled = True
            self.save_state(state)

        try:
            fragments = self.registry.collect_fragments(state)
            self.journal("fragments_collected", plugins=list(fragments))
        except Exception as exc:
            self.set_apply_error(str(exc))
            self.singbox.log("ERROR", str(exc))
            self.journal("failed", stage="collect_fragments", error=str(exc))
            return False

        config = self.singbox.generate_config(state, fragments)
        transaction.advance("snapshot")
        previous_config = None
        if self.singbox.SINGBOX_CONFIG.exists():
            try:
                previous_config = self.singbox.SINGBOX_CONFIG.read_bytes()
            except OSError:
                previous_config = None
        if not self.singbox.write_config(config):
            error = self.singbox.last_error() or "Не удалось записать конфигурацию Sing-Box"
            self.set_apply_error(error)
            self.journal("failed", stage="singbox_config", error=error)
            return False
        transaction.add_rollback(
            "sing-box config",
            lambda: self._restore_singbox_config(previous_config),
            priority=10,
        )
        nft_snapshot = self.nft.snapshot_tproxy()
        transaction.add_rollback(
            "nftables",
            lambda: self._restore_nft_snapshot(nft_snapshot),
            priority=20,
        )
        transaction.advance("apply")
        try:
            self.nft.apply_tproxy(fragments, state.network.tproxy_port)
            self.journal("nft_applied")
        except Exception as exc:
            return fail(
                "nft",
                f"Не удалось применить сетевую конфигурацию: {exc}",
            )

        from hydra.core.sni_router import (
            needs_mux,
            rebuild as rebuild_mux,
            stop as stop_mux,
        )

        self.migrate_haproxy(state)
        mux_active = needs_mux(state)

        if not mux_active:
            stop_mux()
            self._wait_for_port_release()

        try:
            applied_plugins = self.registry.apply_enabled(state)
            enabled = [plugin.meta.name for plugin in self.registry.enabled(state)]
            self.journal("plugins_applied", plugins=enabled)
        except Exception as exc:
            return fail(
                "plugins",
                f"Не удалось применить конфигурацию плагина: {exc}",
            )

        plugin_count = len(applied_plugins)
        for index, (plugin, snapshot) in enumerate(applied_plugins):
            transaction.add_rollback(
                f"plugin {plugin.meta.name}",
                lambda plugin=plugin, snapshot=snapshot: self.registry.rollback(
                    plugin,
                    state,
                    snapshot,
                ),
                priority=30 + plugin_count - index,
            )

        singbox_ok = self.singbox.reload()
        mux_ok = True
        if mux_active:
            self._wait_for_port_release()
            mux_ok = rebuild_mux(state)

        try:
            self.manage_traffic_daemon(state)
        except Exception as exc:
            return fail(
                "traffic_daemon",
                f"Не удалось применить сервис учёта трафика: {exc}",
                reload_restored=True,
            )

        transaction.advance("healthcheck")
        plugin_health = self.registry.health_all(state)
        if plugin_health:
            details = "; ".join(
                f"{name}: {reason}"
                for name, reason in plugin_health.items()
            )
            return fail(
                "plugin_health",
                f"Проверка сервисов не пройдена: {details}",
                reload_restored=True,
            )

        if not singbox_ok or not mux_ok:
            if not singbox_ok:
                error = (
                    self.singbox.last_error()
                    or "Sing-Box не запустился после применения"
                )
            else:
                error = "SNI-маршрутизатор не запустился после применения"
            self.set_apply_error(error)
            return fail("healthcheck", error, reload_restored=True)

        try:
            self.save_state(state)
        except Exception as exc:
            return fail(
                "state",
                f"Не удалось сохранить применённую конфигурацию: {exc}",
                reload_restored=True,
            )

        transaction.commit()
        self.journal("committed")
        return True

    @staticmethod
    def _wait_for_port_release() -> None:
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                if probe.connect_ex(("127.0.0.1", 443)) != 0:
                    break
            time.sleep(0.3)

    def _restore_nft_snapshot(self, snapshot: Any) -> None:
        try:
            self.nft.restore_tproxy(snapshot)
        except Exception as exc:
            self.singbox.log(
                "ERROR",
                f"Не удалось восстановить правила nftables HYDRA: {exc}",
            )

    def _restore_singbox_config(self, previous: bytes | None) -> None:
        try:
            if previous is None:
                self.singbox.SINGBOX_CONFIG.unlink(missing_ok=True)
            else:
                temporary = self.singbox.SINGBOX_CONFIG.with_suffix(
                    ".json.rollback",
                )
                temporary.write_bytes(previous)
                temporary.replace(self.singbox.SINGBOX_CONFIG)
        except OSError as exc:
            self.singbox.log(
                "ERROR",
                f"Failed to restore sing-box config: {exc}",
            )


def restore_state_in_place(target: AppState, snapshot: AppState) -> None:
    """Restore desired state while retaining the target's concurrency token."""
    revision = target.revision
    for field_name in snapshot.__dataclass_fields__:
        if field_name == "revision":
            continue
        setattr(
            target,
            field_name,
            copy.deepcopy(getattr(snapshot, field_name)),
        )
    target.revision = revision


def migrate_haproxy(
    state: AppState,
    *,
    host: Any,
    save_state: Callable[[AppState], None],
) -> None:
    """Perform the one-time HAProxy to Caddy L4 migration."""
    if state.install.get("caddy_l4_migrated", False):
        return

    if shutil.which("systemctl"):
        try:
            result = host.run(["systemctl", "is-enabled", "haproxy"], text=True)
            if result.stdout.strip() == "enabled":
                from hydra.core.sni_router import uninstall_haproxy

                print("  Migration: stopping and disabling HAProxy...")
                uninstall_haproxy()
        except Exception:
            pass

    state.install["caddy_l4_migrated"] = True
    save_state(state)
