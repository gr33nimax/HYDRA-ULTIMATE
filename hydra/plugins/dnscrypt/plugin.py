"""
hydra/plugins/dnscrypt/plugin.py — DNSCrypt-proxy.

Устанавливает и настраивает DNSCrypt-proxy на 127.0.0.1:5300.
Sing-Box использует его как upstream DNS-сервер.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

DNSCRYPT_BIN = Path("/usr/bin/dnscrypt-proxy")
DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
DNSCRYPT_PORT = 5300


class DNSCryptPlugin(BasePlugin):
    meta = PluginMeta(
        name="dnscrypt",
        description="DNSCrypt-proxy: шифрование DNS (DoH/DNSCrypt) на системном уровне",
        category=PluginCategory.ENHANCEMENT,
        version="1.0.0",
    )

    def install(self) -> bool:
        if DNSCRYPT_BIN.exists():
            return True

        r = subprocess.run(
            ["bash", "-c", "apt-get update -qq && apt-get install -y -qq dnscrypt-proxy"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return False

        self._write_default_config()
        return True

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
        return True

    def _write_default_config(self) -> None:
        """Пишет базовый конфиг DNSCrypt-proxy."""
        conf = f"""
listen_addresses = ['127.0.0.1:{DNSCRYPT_PORT}']
server_names = ['quad9-dnscrypt-ip4-filter-pri', 'cloudflare']
max_clients = 250
force_tcp = false
timeout = 3000
keepalive = 30
cert_refresh_delay = 240
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
log_level = 2
use_syslog = true
"""
        DNSCRYPT_CONF.parent.mkdir(parents=True, exist_ok=True)
        DNSCRYPT_CONF.write_text(conf)

    def configure(self, state: AppState) -> ConfigFragment:
        """DNSCrypt не генерирует Sing-Box фрагмент — он работает на системном уровне."""
        return ConfigFragment()

    def status(self) -> PluginStatus:
        installed = DNSCRYPT_BIN.exists()
        running = False
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "dnscrypt-proxy"],
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=bool(DNSCRYPT_CONF.exists()),
            running=running,
            port=DNSCRYPT_PORT,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        state.network.dnscrypt_enabled = True
        state.network.dnscrypt_port = DNSCRYPT_PORT
        self._write_default_config()
        subprocess.run(["systemctl", "enable", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["systemctl", "start", "dnscrypt-proxy"], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        state.network.dnscrypt_enabled = False
        subprocess.run(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["systemctl", "disable", "dnscrypt-proxy"], capture_output=True)
