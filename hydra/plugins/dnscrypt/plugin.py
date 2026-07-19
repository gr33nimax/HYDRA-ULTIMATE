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

def get_dnscrypt_bin() -> Path:
    for p in ["/usr/sbin/dnscrypt-proxy", "/usr/bin/dnscrypt-proxy"]:
        path = Path(p)
        if path.exists():
            return path
    return Path("/usr/sbin/dnscrypt-proxy")

DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
DNSCRYPT_PORT = 5300


class DNSCryptPlugin(BasePlugin):
    meta = PluginMeta(
        name="dnscrypt",
        description="DNSCrypt-proxy: шифрование DNS (DoH/DNSCrypt) на системном уровне",
        category=PluginCategory.ENHANCEMENT,
        version="2.0.0",
    )

    def install(self) -> bool:
        if not self._installed():
            r = subprocess.run(
                ["bash", "-c", "apt-get update -qq && apt-get install -y -qq dnscrypt-proxy"],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode != 0:
                return False

        self._write_default_config()
        service = subprocess.run(
            ["systemctl", "enable", "--now", "dnscrypt-proxy"], capture_output=True
        )
        return service.returncode == 0

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["systemctl", "disable", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["apt-get", "remove", "-y", "-qq", "dnscrypt-proxy"], capture_output=True, timeout=60)
        if DNSCRYPT_CONF.exists():
            DNSCRYPT_CONF.unlink(missing_ok=True)
        return True

    def snapshot(self, state: AppState):
        return {
            "config": DNSCRYPT_CONF.read_bytes() if DNSCRYPT_CONF.exists() else None,
            "running": self.status().running,
        }

    def rollback(self, state: AppState, snapshot) -> bool:
        previous = snapshot or {}
        config = previous.get("config")
        if config is None:
            DNSCRYPT_CONF.unlink(missing_ok=True)
        else:
            DNSCRYPT_CONF.parent.mkdir(parents=True, exist_ok=True)
            tmp = DNSCRYPT_CONF.with_suffix(".toml.rollback")
            tmp.write_bytes(config)
            tmp.replace(DNSCRYPT_CONF)
        if previous.get("running"):
            result = subprocess.run(["systemctl", "restart", "dnscrypt-proxy"], capture_output=True)
        else:
            result = subprocess.run(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
        return result.returncode == 0

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
fallback_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
log_level = 2
use_syslog = true

[sources]
  [sources.'public-resolvers']
  urls = [
      'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
      'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
  ]
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
"""
        DNSCRYPT_CONF.parent.mkdir(parents=True, exist_ok=True)
        DNSCRYPT_CONF.write_text(conf)

    def configure(self, state: AppState) -> ConfigFragment:
        """Возвращает DNS-конфиг для Sing-Box."""
        dns_config = {
            "servers": [
                {
                    "tag": "dnscrypt-local",
                    "address": f"127.0.0.1:{DNSCRYPT_PORT}",
                    "detour": "direct",
                }
            ],
            "rules": [],
        }
        return ConfigFragment(dns=dns_config)

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        enabled = False
        try:
            from hydra.core.state import load_state
            plugin_state = load_state().protocols.get(self.meta.name)
            enabled = plugin_state.enabled if plugin_state else DNSCRYPT_CONF.exists()
        except Exception:
            enabled = DNSCRYPT_CONF.exists()
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "dnscrypt-proxy"],
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=running,
            port=DNSCRYPT_PORT,
        )

    @staticmethod
    def _installed() -> bool:
        return Path("/usr/sbin/dnscrypt-proxy").exists() or Path("/usr/bin/dnscrypt-proxy").exists()

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        state.network.dnscrypt_enabled = True
        state.network.dnscrypt_port = DNSCRYPT_PORT
        # Не затираем выбранные пользователем server_names при каждом toggle.
        if not DNSCRYPT_CONF.exists():
            self._write_default_config()
        subprocess.run(["systemctl", "enable", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["systemctl", "start", "dnscrypt-proxy"], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        state.network.dnscrypt_enabled = False
        subprocess.run(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
        subprocess.run(["systemctl", "disable", "dnscrypt-proxy"], capture_output=True)
