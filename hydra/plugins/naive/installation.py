"""NaiveProxy binary and systemd-unit installation."""
from __future__ import annotations

import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .constants import NaiveRuntimeLayout


if TYPE_CHECKING:
    _RuntimeLayout = Callable[[], NaiveRuntimeLayout]
    _HostBackend = Callable[[], Any]
    _Installed = Callable[[], bool]
    _ValidateCaddy = Callable[..., str | None]


class NaiveInstallationMixin:
    """Install or remove host assets without owning runtime reconciliation."""

    if TYPE_CHECKING:
        _runtime_layout: _RuntimeLayout
        _host_backend: _HostBackend
        _installed: _Installed
        _validate_caddy: _ValidateCaddy

    def install(self) -> bool:
        layout = self._runtime_layout()
        if self._installed():
            return True
        if not layout.binary.is_file():
            print("  Устанавливаю caddy-naive с поддержкой UoT...")
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
        for directory in (
            layout.config_dir,
            layout.log_dir,
            layout.data_dir,
        ):
            if directory.exists():
                try:
                    shutil.rmtree(directory, ignore_errors=True)
                except OSError:
                    continue
        return True

    def _download_binary(self, config_path: Path | None = None) -> bool:
        from hydra.core import sni_router, sni_router_install

        host = self._host_backend()
        layout = self._runtime_layout()
        settings = replace(
            sni_router._install_settings(), binary=layout.binary,
            caddy_version="v2.10.2",
        )
        existed = layout.binary.exists()
        layout.binary.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="hydra-naive-") as directory:
            probe = Path(directory) / "Caddyfile"
            probe.write_text(
                ":8080 {\n forward_proxy {\n"
                "  upstream socks5://127.0.0.1:1080\n  passthrough_uot\n }\n}\n",
                encoding="utf-8",
            )
            success = sni_router_install.install(
                None, settings, host, force=True, installed=lambda: False,
                forward_proxy=True, layer4=False,
                ensure_go=lambda: sni_router_install.ensure_modern_go(
                    settings, host, official_digest=sni_router._official_go_digest,
                ),
                build=lambda args, env: sni_router_install.run_caddy_build(
                    args, env, host=host, timeout=settings.build_timeout,
                ),
                validate=lambda binary: not self._validate_caddy(
                    config_path or probe, binary=binary,
                ),
            )
        if success and existed:
            self._binary_replaced = True
        return success

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
            f'Environment="XDG_DATA_HOME={layout.data_dir}"\n'
            f'Environment="XDG_CONFIG_HOME={layout.data_dir}"\n'
            "LimitNOFILE=1048576\n"
            f"ReadWritePaths={layout.config_dir} {layout.log_dir} "
            f"{decoy_dir} {layout.data_dir}\n"
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
