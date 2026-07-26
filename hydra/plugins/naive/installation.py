"""NaiveProxy binary and systemd-unit installation."""
from __future__ import annotations

import shutil

from .constants import DATA_DIR, DOWNLOAD_DIR


class NaiveInstallationMixin:
    """Install or remove host assets without owning runtime reconciliation."""

    def install(self) -> bool:
        if self._installed():
            return True
        print("  Скачиваю caddy-naive...")
        if not self._download_binary():
            print("  Не удалось установить caddy-naive.")
            return False
        self._install_service()
        return self._installed()

    def uninstall(self) -> bool:
        layout = self._runtime_layout()
        host = self._host_backend()
        host.run(
            ["systemctl", "stop", layout.service_name],
            capture_output=True,
        )
        host.run(
            ["systemctl", "disable", layout.service_name],
            capture_output=True,
        )
        if layout.service_file.exists():
            layout.service_file.unlink()
        host.run(["systemctl", "daemon-reload"], capture_output=True)
        host.run(["systemctl", "reset-failed"], capture_output=True)

        if layout.binary.exists():
            layout.binary.unlink()
        for directory in (layout.config_dir, layout.log_dir, DATA_DIR):
            if directory.exists():
                shutil.rmtree(directory, ignore_errors=True)
        return True

    def _download_binary(self) -> bool:
        from hydra.utils.net import detect_arch

        layout = self._runtime_layout()
        architecture = detect_arch()
        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        binary = DOWNLOAD_DIR / f"caddy-linux-{architecture}"
        if not self._download_asset(
            layout.github_repo,
            f"caddy-linux-{architecture}",
            binary,
        ):
            return False
        if not self._verify_binary(binary):
            return False

        if layout.binary.exists():
            try:
                layout.binary.unlink()
            except Exception:
                pass
        shutil.copy2(str(binary), str(layout.binary))
        layout.binary.chmod(0o755)
        return True

    def _install_service(self) -> None:
        from hydra.core.decoy import DECOY_DIRS

        layout = self._runtime_layout()
        decoy_dir = DECOY_DIRS.get("naive", layout.fake_site_dir)
        decoy_dir.mkdir(parents=True, exist_ok=True)
        layout.service_file.write_text(
            "[Unit]\n"
            "Description=NaiveProxy (caddy-forwardproxy-naive)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=notify\n"
            f"ExecStart={layout.binary} run "
            f"--config {layout.caddyfile} --adapter caddyfile\n"
            "ExecReload=/bin/kill -USR1 $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=1\n"
            "TimeoutStopSec=5\n"
            'Environment="XDG_DATA_HOME=/var/lib/caddy-naive"\n'
            'Environment="XDG_CONFIG_HOME=/var/lib/caddy-naive"\n'
            "LimitNOFILE=1048576\n"
            f"ReadWritePaths={layout.config_dir} {layout.log_dir} "
            f"{decoy_dir} /var/lib/caddy-naive\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
        )
        host = self._host_backend()
        host.run(["systemctl", "daemon-reload"], capture_output=True)
        host.run(
            ["systemctl", "enable", layout.service_name],
            capture_output=True,
        )
