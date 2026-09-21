"""mtproto.zig transport plugin."""

from __future__ import annotations

import shutil
from pathlib import Path

from hydra.contracts import BackupResource, ConfigFragment
from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.utils.downloader import verify_elf
from hydra.utils.net import public_ip

from . import configuration, installation, observation, profiles, runtime
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
    WORK_DIR,
)
from .credentials import derive_secret, derive_username


class MtprotoZigPlugin(BasePlugin):
    meta = PluginMeta(
        name="mtproto_zig",
        display_name="MTProto Zig",
        description="mtproto.zig FakeTLS MTProxy",
        category=PluginCategory.TRANSPORT,
        needs_domain=True,
        required_commands=("systemctl",),
        actions=("update_binary",),
        tls_domain_source="protocol",
        connection_source="none",
        config_defaults=((ROUTE_KEY, configuration.route_metadata()),),
        backup_resources=(
            BackupResource(str(CONFIG_DIR), "tree"),
            BackupResource(str(WORK_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
        ),
    )

    def __init__(self) -> None:
        self._pending_config: str | None = None
        self._install_failure = ""
        self._apply_failure = ""

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
        ):
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
        return installation.uninstall(
            host=HOST,
            service=SERVICE_NAME,
            service_file=SERVICE_FILE,
            binary=BIN_PATH,
            directories=(CONFIG_DIR, WORK_DIR),
        )

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        self._pending_config, fragment = configuration.plan_configuration(state)
        return fragment

    def apply(self, state: PluginStateAccess) -> bool:
        self._apply_failure = ""
        return runtime.apply(
            self._pending_config,
            host=HOST,
            config_file=CONFIG_FILE,
            service=SERVICE_NAME,
            binary=BIN_PATH,
            on_failure=self._note_apply_failure,
        )

    def _note_apply_failure(self, stage: str) -> None:
        self._apply_failure = stage

    def snapshot(self, state: PluginStateAccess) -> dict:
        return runtime.snapshot(config_file=CONFIG_FILE, service_file=SERVICE_FILE, running=self.status().running)

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        return runtime.rollback(
            snapshot, host=HOST, config_file=CONFIG_FILE, service_file=SERVICE_FILE, service=SERVICE_NAME
        )

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("mtproto_zig", {}).update(
            username=derive_username(user.uuid), secret=derive_secret(user.uuid)
        )

    def on_enable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "disable", "--now", SERVICE_NAME], capture_output=True)

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        return profiles.client_link(user, state, resolve_public_ip=public_ip)

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        return profiles.generate_client_config(self.client_link(user, state))

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        installed = self._installed()
        result = (
            HOST.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True) if installed else None
        )
        running = bool(result and result.returncode == 0 and result.stdout.strip() == "active")
        return PluginStatus(
            installed=installed,
            enabled=CONFIG_FILE.exists(),
            running=running,
            port=INTERNAL_PORT,
            info={"traffic_file": str(TOTALS_FILE)},
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        totals, _reason = observation.traffic(state, totals_file=TOTALS_FILE)
        return totals

    def traffic_snapshot(self, state: PluginStateAccess) -> dict[str, int] | None:
        return self.traffic(state)

    def update_binary(self) -> bool:
        return installation.download_binary(host=HOST, repo=GITHUB_REPO, binary=BIN_PATH)

    @staticmethod
    def _installed() -> bool:
        candidate = BIN_PATH if BIN_PATH.exists() else (Path(found) if (found := shutil.which("mtproto-zig")) else None)
        return bool(candidate and verify_elf(candidate))
