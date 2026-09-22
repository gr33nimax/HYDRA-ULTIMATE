"""mtproto.zig transport plugin."""

from __future__ import annotations

import shutil
from pathlib import Path

from hydra.contracts import BackupResource, ConfigFragment
from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import BasePlugin, HealthResult, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.utils.downloader import verify_elf
from hydra.utils.net import public_ip

from . import bridge_probe, configuration, installation, observation, profiles, runtime, web_runtime
from .constants import (
    BIN_PATH,
    CONFIG_DIR,
    CONFIG_FILE,
    GITHUB_REPO,
    INTERNAL_PORT,
    ROUTE_KEY,
    SERVICE_FILE,
    SERVICE_NAME,
    TOTALS_FILE,
    WEB_SERVICE_FILE,
    WEB_SERVICE_NAME,
    WORK_DIR,
)
from .credentials import bridge_capability, derive_secret, derive_username


class MtprotoZigPlugin(BasePlugin):
    meta = PluginMeta(
        name="mtproto_zig",
        display_name="MTProto Zig",
        description="mtproto.zig FakeTLS MTProxy",
        category=PluginCategory.TRANSPORT,
        needs_domain=True,
        required_commands=("systemctl",),
        actions=("update_binary",),
        commands=("set_web_settings",),
        tls_domain_source="protocol",
        connection_source="none",
        config_defaults=((ROUTE_KEY, configuration.route_metadata()),),
        backup_resources=(
            BackupResource(str(CONFIG_DIR), "tree"),
            BackupResource(str(WORK_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
            BackupResource(str(WEB_SERVICE_FILE), "file"),
        ),
    )

    def __init__(self) -> None:
        self._pending_config: str | None = None
        self._install_failure = ""
        self._apply_failure = ""
        self._traffic_reason = ""

    def install(self) -> bool:
        self._install_failure = ""
        if not self._installed() and not installation.download_binary(
            host=HOST,
            repo=GITHUB_REPO,
            binary=BIN_PATH,
            on_failure=self._note_install_failure,
        ):
            return False
        if not installation.ensure_service_user(HOST):
            self._note_install_failure("не удалось создать сервисного пользователя mtproto-zig")
            return False
        if not installation.write_service(
            host=HOST,
            service_file=SERVICE_FILE,
            binary=BIN_PATH,
            config=CONFIG_FILE,
            work_dir=WORK_DIR,
            service=SERVICE_NAME,
            on_failure=self._note_install_failure,
        ):
            if not self._install_failure:
                self._note_install_failure("не удалось записать systemd-юнит mtproto-zig")
            return False
        return True

    def install_failure(self) -> str:
        """Redacted stage of the last failed install, for operator diagnostics."""
        return self._install_failure

    def apply_failure(self) -> str:
        """Redacted stage of the last failed apply, for operator diagnostics."""
        return self._apply_failure

    def _note_install_failure(self, stage: str) -> None:
        self._install_failure = stage

    def uninstall(self) -> bool:
        installation.uninstall_web(
            host=HOST,
            service=WEB_SERVICE_NAME,
            service_file=WEB_SERVICE_FILE,
        )
        return installation.uninstall(
            host=HOST,
            service=SERVICE_NAME,
            service_file=SERVICE_FILE,
            binary=BIN_PATH,
            directories=(CONFIG_DIR, WORK_DIR),
        )

    def needs_tls_domain(self, state: PluginStateAccess) -> bool:
        """FakeTLS owns the handshake; Caddy only routes its SNI."""
        del state
        return False

    def certificate_requirements(self, state: PluginStateAccess) -> tuple[tuple[str, str, str], ...]:
        """Additional public certificates as ``(domain, cert_key, key_key)`` pairs.

        The borrowed FakeTLS cover domain never needs one: the proxy speaks that
        handshake itself. Only an active WEB bridge terminates TLS in the shared
        frontend, so only it needs a real certificate.
        """
        config = self._config(state)
        if not configuration.web_active(config):
            return ()
        domain = configuration.web_domain(config)
        if not domain:
            raise ValueError("Для WEB-режима MTProto Zig нужен отдельный домен релея")
        return ((domain, "web_cert_file", "web_key_file"),)

    def set_web_settings(
        self,
        state: PluginStateAccess,
        mode: str,
        domain: str = "",
        confirm_host_change: object = False,
    ) -> bool:
        """Persist the WEB access mode and the route set it requires.

        Validation and route policy live in :mod:`configuration`; this hook keeps
        the plugin command boundary and its signature stable.
        """
        return configuration.set_web_settings(state, mode, domain, confirm_host_change)

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        self._pending_config, fragment = configuration.plan_configuration(state)
        return fragment

    def apply(self, state: PluginStateAccess) -> bool:
        """Apply the data plane, then stage the WEB relay it advertises.

        The exclusive ``only = true`` mode is never committed here: the Zig
        config stays at ``only = false`` until :meth:`finalize_apply` proves the
        rebuilt frontend. For ``web-only`` the FakeTLS passthrough route itself
        was already dropped from desired state by
        :func:`configuration.set_web_settings`.
        """
        self._apply_failure = ""
        config = self._config(state)
        applied = runtime.apply(
            self._pending_config,
            host=HOST,
            config_file=CONFIG_FILE,
            work_dir=WORK_DIR,
            service=SERVICE_NAME,
            binary=BIN_PATH,
            on_failure=self._note_apply_failure,
        )
        if not applied:
            return False
        if not configuration.web_active(config):
            return web_runtime.stop(
                host=HOST,
                service=WEB_SERVICE_NAME,
                service_file=WEB_SERVICE_FILE,
                on_failure=self._note_apply_failure,
            )
        return web_runtime.apply(
            host=HOST,
            binary=BIN_PATH,
            config_file=CONFIG_FILE,
            work_dir=WORK_DIR,
            service=WEB_SERVICE_NAME,
            service_file=WEB_SERVICE_FILE,
            proxy_service=SERVICE_NAME,
            on_failure=self._note_apply_failure,
        )

    def finalize_apply(self, state: PluginStateAccess) -> bool:
        """Prove the WEB path through the rebuilt frontend before narrowing access.

        The readiness check is the authenticated bridge handshake, so it needs a
        real user secret; ``web-only`` is refused when no capability can be built,
        because the direct entrance must not be closed on an unproven bridge.
        """
        config = self._config(state)
        mode = configuration.web_mode(config)
        if mode == "off":
            return True
        capability = self._bridge_capability(state)
        if not capability:
            if mode != "web-only":
                return True
            self._note_apply_failure(
                "WEB-мост нельзя проверить: нет ни одного активного пользователя",
            )
            return False
        healthy, reason = bridge_probe.probe_bridge(
            configuration.web_domain(config),
            capability=capability,
        )
        if not healthy:
            self._note_apply_failure(f"WEB-мост не подтверждён: {reason}")
            return False
        if mode != "web-only":
            return True
        committed, _fragment = configuration.plan_configuration(state, web_only=True)
        return runtime.apply(
            committed,
            host=HOST,
            config_file=CONFIG_FILE,
            work_dir=WORK_DIR,
            service=SERVICE_NAME,
            binary=BIN_PATH,
            on_failure=self._note_apply_failure,
        )

    @classmethod
    def _bridge_capability(cls, state: PluginStateAccess) -> str:
        """Build the probe capability from the first active user's secret."""
        host = configuration.web_domain(cls._config(state))
        for user in state.users:
            if not user.blocked:
                return bridge_capability(derive_secret(user.uuid), host)
        return ""

    @staticmethod
    def _config(state: PluginStateAccess) -> dict:
        protocol = state.protocols.get("mtproto_zig")
        return dict(protocol.config) if protocol else {}

    def _note_apply_failure(self, stage: str) -> None:
        self._apply_failure = stage

    def snapshot(self, state: PluginStateAccess) -> dict:
        """Capture both units fresh: a stale capture must never drive a rollback."""
        snapshot = runtime.snapshot(config_file=CONFIG_FILE, service_file=SERVICE_FILE, running=self.status().running)
        snapshot["web"] = web_runtime.snapshot(
            service_file=WEB_SERVICE_FILE,
            running=web_runtime.running(HOST, WEB_SERVICE_NAME),
        )
        return snapshot

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        restored = runtime.rollback(
            snapshot, host=HOST, config_file=CONFIG_FILE, service_file=SERVICE_FILE, service=SERVICE_NAME
        )
        return (
            web_runtime.rollback(
                (snapshot or {}).get("web"),
                host=HOST,
                service=WEB_SERVICE_NAME,
                service_file=WEB_SERVICE_FILE,
            )
            and restored
        )

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("mtproto_zig", {}).update(
            username=derive_username(user.uuid), secret=derive_secret(user.uuid)
        )

    def on_enable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "disable", "--now", SERVICE_NAME], capture_output=True)
        # The relay is enabled on its own and requires the main unit, so leaving it
        # enabled would pull a disabled proxy back up at boot.
        web_runtime.stop(
            host=HOST,
            service=WEB_SERVICE_NAME,
            service_file=WEB_SERVICE_FILE,
            on_failure=self._note_apply_failure,
        )

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        return profiles.client_link(user, state, resolve_public_ip=public_ip)

    def client_links(self, user: User, state: PluginStateAccess) -> list[str]:
        return profiles.client_links(user, state, resolve_public_ip=public_ip)

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        return profiles.generate_client_config(self.client_link(user, state))

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        installed = self._installed()
        result = (
            HOST.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True) if installed else None
        )
        unit_state = (result.stdout or "").strip() if result else ""
        running = bool(result and result.returncode == 0 and unit_state == "active")
        config = self._config(state) if state is not None else {}
        mode = configuration.web_mode(config)
        info: dict = {
            "traffic_file": str(TOTALS_FILE),
            "traffic_source": self._traffic_reason or "ok",
            "state": unit_state,
            "web_mode": mode,
        }
        if mode == "off":
            info["link_mode"] = "direct FakeTLS"
            return PluginStatus(
                installed=installed,
                enabled=CONFIG_FILE.exists(),
                running=running,
                port=INTERNAL_PORT,
                info=info,
            )
        web_state = web_runtime.service_state(HOST, WEB_SERVICE_NAME)
        info.update(
            {
                "web_domain": configuration.web_domain(config),
                "web_state": web_state,
                "link_mode": "WEB bridge only" if mode == "web-only" else "FakeTLS + WEB bridge",
            },
        )
        return PluginStatus(
            installed=installed,
            enabled=CONFIG_FILE.exists(),
            running=running and web_state == "active",
            port=INTERNAL_PORT,
            info=info,
        )

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        """Name the unit state and where to look when mtproto-zig is not running."""
        current = self.status(state)
        if current.running:
            reason = str(current.info.get("traffic_source", "") or "")
            if reason and reason != "ok":
                return HealthResult(
                    True,
                    f"источник трафика недоступен: {reason}",
                    "warning",
                )
            return HealthResult(True)
        web_state = str(current.info.get("web_state", "") or "")
        if web_state and web_state != "active":
            return HealthResult(
                False,
                f"служба {WEB_SERVICE_NAME} не активна (state={web_state}): смотрите journalctl -u {WEB_SERVICE_NAME}",
                "error",
            )
        unit_state = str(current.info.get("state", "") or "unknown")
        return HealthResult(
            False,
            f"служба {SERVICE_NAME} не активна (state={unit_state}): смотрите journalctl -u {SERVICE_NAME}",
            "error",
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return self.traffic_snapshot(state) or {}

    def traffic_snapshot(self, state: PluginStateAccess) -> dict[str, int] | None:
        """Read the cumulative metrics counters; ``None`` means unavailable."""
        totals, reason = observation.traffic(state, totals_file=TOTALS_FILE)
        self._traffic_reason = reason
        return totals

    def traffic_source_reason(self, state: PluginStateAccess) -> str:
        """Reason the last counter scrape failed; empty when it succeeded."""
        del state
        return self._traffic_reason

    def update_binary(self) -> bool:
        return installation.download_binary(host=HOST, repo=GITHUB_REPO, binary=BIN_PATH)

    @staticmethod
    def _installed() -> bool:
        candidate = BIN_PATH if BIN_PATH.exists() else (Path(found) if (found := shutil.which("mtproto-zig")) else None)
        return bool(candidate and verify_elf(candidate))
