"""Hydra-owned Telemt plugin facade."""

from __future__ import annotations

import shutil
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import BasePlugin, ConfigFragment, HealthResult, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.utils.downloader import verify_elf
from hydra.utils.net import public_ip

from . import configuration, installation, observation, profiles, runtime
from .constants import (
    BIN_PATH,
    CONFIG_DIR,
    CONFIG_FILE,
    DEFAULT_PORT,
    GITHUB_REPO,
    SERVICE_FILE,
    SERVICE_NAME,
    WORK_DIR,
)
from .credentials import derive_secret, derive_username, make_tls_secret


class TelemtPlugin(BasePlugin):
    meta = PluginMeta(
        name="telemt",
        description="Telemt Fake TLS MTProxy",
        category=PluginCategory.TRANSPORT,
        version="3.5.7",
        needs_domain=False,
        required_commands=("systemctl",),
        actions=("update_binary",),
        backup_resources=(
            BackupResource(str(CONFIG_DIR), "tree"),
            BackupResource(str(WORK_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
        ),
    )

    def __init__(self) -> None:
        self._pending_cfg: str | None = None
        self._install_failure = ""
        self._apply_failure = ""
        self._traffic_reason = ""

    def install(self) -> bool:
        self._install_failure = ""
        return installation.install(
            host=HOST,
            repo=GITHUB_REPO,
            bin_path=BIN_PATH,
            work_dir=WORK_DIR,
            service_file=SERVICE_FILE,
            config_file=CONFIG_FILE,
            service_name=SERVICE_NAME,
            on_failure=self._note_install_failure,
        )

    def install_failure(self) -> str:
        """Redacted stage of the last failed install, for operator diagnostics."""
        return self._install_failure

    def apply_failure(self) -> str:
        """Redacted stage of the last failed apply, for operator diagnostics."""
        return self._apply_failure

    def _note_install_failure(self, stage: str) -> None:
        self._install_failure = stage

    def uninstall(self) -> bool:
        return installation.uninstall(
            host=HOST,
            service_name=SERVICE_NAME,
            service_file=SERVICE_FILE,
            bin_path=BIN_PATH,
            directories=(CONFIG_DIR, WORK_DIR),
        )

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        self._pending_cfg, fragment = configuration.plan_configuration(state)
        return fragment

    def apply(self, state: PluginStateAccess) -> bool:
        self._apply_failure = ""
        return runtime.apply(
            self._pending_cfg,
            host=HOST,
            config_file=CONFIG_FILE,
            work_dir=WORK_DIR,
            service_name=SERVICE_NAME,
            on_failure=self._note_apply_failure,
        )

    def _note_apply_failure(self, stage: str) -> None:
        self._apply_failure = stage

    def snapshot(self, state: PluginStateAccess) -> dict:
        return runtime.snapshot(
            config_file=CONFIG_FILE,
            service_file=SERVICE_FILE,
            running=self.status().running,
        )

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        return runtime.rollback(
            snapshot,
            host=HOST,
            config_file=CONFIG_FILE,
            service_file=SERVICE_FILE,
            service_name=SERVICE_NAME,
        )

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("telemt", {}).update(
            username=derive_username(user.uuid),
            secret=derive_secret(user.uuid),
        )

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        """Access removal is rendered from state by the common lifecycle."""

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        """Blocked users are excluded by the common configuration renderer."""

    def on_enable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "disable", "--now", SERVICE_NAME], capture_output=True)

    def client_links(self, user: User, state: PluginStateAccess) -> list[str]:
        return profiles.client_links(user, state, resolve_public_ip=public_ip)

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        links = self.client_links(user, state)
        return links[0] if links else ""

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        return profiles.generate_client_config(self.client_link(user, state))

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        result = observation.status(
            host=HOST,
            bin_path=BIN_PATH,
            config_file=CONFIG_FILE,
            service_name=SERVICE_NAME,
            default_port=DEFAULT_PORT,
            is_installed=self._installed(),
        )
        result.info["traffic_source"] = self._traffic_reason or "ok"
        return result

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        """Name the unit state and where to look when Telemt is not running."""
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
        unit_state = str(current.info.get("state", "") or "unknown")
        return HealthResult(
            False,
            f"служба {SERVICE_NAME} не активна (state={unit_state}): смотрите journalctl -u {SERVICE_NAME}",
            "error",
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        """Accumulated per-user totals owned by the accounting service."""
        return super().traffic(state)

    def traffic_snapshot(self, state: PluginStateAccess) -> dict[str, int] | None:
        """Read the cumulative control-API counter; ``None`` means unavailable."""
        totals, reason = observation.traffic(
            state,
            derive_username=derive_username,
        )
        self._traffic_reason = reason
        return totals

    def traffic_source_reason(self, state: PluginStateAccess) -> str:
        """Reason the last counter read failed; empty when it succeeded."""
        del state
        return self._traffic_reason

    def update_binary(self) -> bool:
        return installation.update_binary(
            host=HOST,
            repo=GITHUB_REPO,
            bin_path=BIN_PATH,
            service_name=SERVICE_NAME,
        )

    _derive_username = staticmethod(derive_username)
    _derive_secret = staticmethod(derive_secret)
    _make_tls_secret = staticmethod(make_tls_secret)

    @staticmethod
    def _installed() -> bool:
        candidate = BIN_PATH if BIN_PATH.exists() else (Path(found) if (found := shutil.which("telemt")) else None)
        return bool(candidate and verify_elf(candidate))

    @staticmethod
    def _build_toml(
        port: int,
        ipv4: bool,
        ipv6: bool,
        tls_domain: str,
        users: dict[str, str],
        use_middle_proxy: bool = False,
        client_mss: str = "",
    ) -> str:
        return configuration.build_toml(port, ipv4, ipv6, tls_domain, users, use_middle_proxy, client_mss)
