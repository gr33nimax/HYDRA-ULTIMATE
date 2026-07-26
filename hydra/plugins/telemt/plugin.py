"""Telemt MTProxy plugin facade.

Policy, installation, observation, profiles and runtime side effects live in
focused sibling modules.  Constants and historical helper methods stay exposed
here for callers and monkeypatch-based integrations.
"""
from __future__ import annotations

import platform
import shutil
import tempfile
import time
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.core.install_layout import project_root, python_executable
from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.utils.downloader import (
    download_github_asset,
    extract_tarball,
    latest_release,
    verify_elf,
)
from hydra.utils.net import public_ip

from . import configuration, installation, observation, profiles, runtime
from .constants import (
    BIN_PATH,
    CONFIG_DIR,
    CONFIG_FILE,
    DEFAULT_PORT,
    GITHUB_REPO,
    LOG_FILE,
    PERFORMANCE_LIMITS_FILE,
    PERFORMANCE_SYSCTL_FILE,
    SERVICE_FILE,
    SERVICE_NAME,
    STATS_CRON_FILE,
    WORK_DIR,
)
from .credentials import derive_secret, derive_username, make_tls_secret


class _RestartingHost:
    """Translate Telemt's legacy reload request into a deterministic restart."""

    def __init__(self, host) -> None:
        self._host = host

    def __getattr__(self, name):
        return getattr(self._host, name)

    def run(self, command: list[str], **options):
        if command == ["systemctl", "reload-or-restart", SERVICE_NAME]:
            command = ["systemctl", "restart", SERVICE_NAME]
        return self._host.run(command, **options)


class TelemtPlugin(BasePlugin):
    meta = PluginMeta(
        name="telemt",
        description="Telemt MTProxy: Rust MTProto proxy, multi-user secret",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
        required_commands=("systemctl",),
        actions=(
            "apply_optimizations",
            "remove_optimizations",
            "update_binary",
        ),
        backup_resources=(
            BackupResource(str(CONFIG_DIR), "tree"),
            BackupResource(str(WORK_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
            BackupResource(str(STATS_CRON_FILE), "file"),
            BackupResource(str(PERFORMANCE_SYSCTL_FILE), "file"),
            BackupResource(str(PERFORMANCE_LIMITS_FILE), "file"),
        ),
    )

    def __init__(self):
        self._pending_cfg: str | None = None

    @staticmethod
    def apply_optimizations() -> bool:
        return runtime.apply_optimizations(
            host=HOST,
            sysctl_file=PERFORMANCE_SYSCTL_FILE,
            limits_file=PERFORMANCE_LIMITS_FILE,
        )

    @staticmethod
    def remove_optimizations() -> bool:
        return runtime.remove_optimizations(
            host=HOST,
            paths=(
                STATS_CRON_FILE,
                PERFORMANCE_SYSCTL_FILE,
                PERFORMANCE_LIMITS_FILE,
            ),
        )

    def install(self) -> bool:
        if not self._installed():
            print("  Скачиваю telemt...")
            if not self._download_binary():
                print("  Не удалось установить telemt.")
                return False
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        # Repair partial installs where the binary survived but the unit did not.
        self._install_service()
        return self._installed() and SERVICE_FILE.exists()

    def uninstall(self) -> bool:
        try:
            from .telemt_ios_fix import disable_ios_fix
            from .telemt_syn_limiter import disable_syn_limiter

            disable_ios_fix()
            disable_syn_limiter()
        except Exception:
            pass
        removed = installation.uninstall(
            host=HOST,
            service_name=SERVICE_NAME,
            service_file=SERVICE_FILE,
            bin_path=BIN_PATH,
            directories=(CONFIG_DIR, WORK_DIR),
        )
        STATS_CRON_FILE.unlink(missing_ok=True)
        return removed

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        self._pending_cfg, fragment = configuration.plan_configuration(state)
        return fragment

    def apply(self, state: PluginStateAccess) -> bool:
        runtime_root = project_root(Path(__file__).resolve().parents[3])
        applied = runtime.apply(
            self._pending_cfg,
            state,
            host=_RestartingHost(HOST),
            config_dir=CONFIG_DIR,
            work_dir=WORK_DIR,
            config_file=CONFIG_FILE,
            cron_file=STATS_CRON_FILE,
            service_name=SERVICE_NAME,
            project_root=runtime_root,
        )
        if not applied:
            return False
        if STATS_CRON_FILE.exists():
            cron = STATS_CRON_FILE.read_text(encoding="utf-8")
            cron = cron.replace(
                " python3 -c ",
                f" {python_executable(runtime_root)} -c ",
            )
            STATS_CRON_FILE.write_text(cron, encoding="utf-8")

        # Optional firewall features can drift after reboot/backend refresh.
        try:
            from . import telemt_ios_fix as ios_fix

            ios_config = ios_fix._load_state()
            if ios_config.enabled:
                ok, message = ios_fix._apply_rules(ios_config)
                if not ok:
                    print(f"  [telemt] iOS-фикс не применён: {message}")
        except Exception as exc:
            print(f"  [telemt] Ошибка восстановления iOS-фикса: {exc}")
        try:
            from . import telemt_syn_limiter as syn_limiter

            syn_config = syn_limiter._load_state()
            if syn_config.enabled:
                ok, message = syn_limiter._apply_rules(syn_config)
                if not ok:
                    print(f"  [telemt] SYN-limiter не применён: {message}")
        except Exception as exc:
            print(f"  [telemt] Ошибка восстановления SYN-limiter: {exc}")

        for _ in range(5):
            active = HOST.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True,
                text=True,
            )
            if active.stdout.strip() == "active":
                return True
            time.sleep(0.5)
        return False

    def snapshot(self, state: PluginStateAccess):
        return runtime.snapshot(
            config_file=CONFIG_FILE,
            service_file=SERVICE_FILE,
            cron_file=STATS_CRON_FILE,
            running=self.status().running,
        )

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        return runtime.rollback(
            snapshot,
            host=HOST,
            config_file=CONFIG_FILE,
            service_file=SERVICE_FILE,
            cron_file=STATS_CRON_FILE,
            service_name=SERVICE_NAME,
        )

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("telemt", {})
        user.credentials["telemt"]["username"] = self._derive_username(
            user.uuid
        )
        user.credentials["telemt"]["secret"] = self._derive_secret(user.uuid)

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        return profiles.generate_client_config(self.client_link(user, state))

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        links = self.client_links(user, state)
        return links[-1] if links else ""

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> list[str]:
        from .telemt_ios_fix import status as ios_status

        return profiles.client_links(
            user,
            state,
            resolve_public_ip=public_ip,
            ios_status=ios_status,
        )

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        return observation.status(
            host=HOST,
            bin_path=BIN_PATH,
            config_file=CONFIG_FILE,
            service_name=SERVICE_NAME,
            default_port=DEFAULT_PORT,
            is_installed=self._installed(),
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return observation.traffic(
            state,
            stats_file=WORK_DIR / "stats.json",
            derive_username=self._derive_username,
        )

    def traffic_snapshot(
        self,
        state: PluginStateAccess,
    ) -> dict[str, int] | None:
        return self.traffic(state)

    def connected_clients(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        return []

    def on_enable(self, state: PluginStateAccess) -> None:
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: PluginStateAccess) -> None:
        HOST.run(
            ["systemctl", "disable", "--now", SERVICE_NAME],
            capture_output=True,
        )

    _derive_username = staticmethod(derive_username)
    _derive_secret = staticmethod(derive_secret)
    _make_tls_secret = staticmethod(make_tls_secret)

    @staticmethod
    def _installed() -> bool:
        candidate = BIN_PATH if BIN_PATH.exists() else (
            Path(found) if (found := shutil.which("telemt")) else None
        )
        return bool(candidate and verify_elf(candidate))

    def _download_binary(self) -> bool:
        arch = (
            "aarch64"
            if platform.machine().lower() in ("aarch64", "arm64")
            else "x86_64"
        )
        asset_pattern = f"telemt-{arch}-linux-gnu.tar.gz"
        destination = Path(tempfile.gettempdir()) / "telemt-install"
        destination.mkdir(parents=True, exist_ok=True)
        if latest_release(GITHUB_REPO) == "unknown":
            return False
        return self._download_and_extract(
            asset_pattern,
            destination,
            destination / asset_pattern,
        )

    def update_binary(self) -> bool:
        return self._download_binary()

    def _download_and_extract(
        self,
        asset_pattern: str,
        dest: Path,
        archive: Path,
    ) -> bool:
        extract_dir = dest / "extracted"
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        installed = installation.download_and_extract(
            asset_pattern,
            dest,
            archive,
            repo=GITHUB_REPO,
            bin_path=BIN_PATH,
            download_asset=download_github_asset,
            extract_archive=extract_tarball,
            verify_binary=verify_elf,
        )
        if not installed and BIN_PATH.exists() and not verify_elf(BIN_PATH):
            BIN_PATH.unlink(missing_ok=True)
        return installed

    @staticmethod
    def _install_service() -> None:
        installation.write_service(
            host=HOST,
            work_dir=WORK_DIR,
            service_file=SERVICE_FILE,
            bin_path=BIN_PATH,
            config_file=CONFIG_FILE,
            service_name=SERVICE_NAME,
        )
        service = SERVICE_FILE.read_text(encoding="utf-8")
        service = service.replace(
            "Wants=network-online.target\n\n",
            "Wants=network-online.target\n"
            "StartLimitIntervalSec=60\n"
            "StartLimitBurst=10\n\n",
        ).replace("RestartSec=10\n", "RestartSec=2\n")
        SERVICE_FILE.write_text(service, encoding="utf-8")
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)

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
        return configuration.build_toml(
            port,
            ipv4,
            ipv6,
            tls_domain,
            users,
            use_middle_proxy,
            client_mss,
        )
