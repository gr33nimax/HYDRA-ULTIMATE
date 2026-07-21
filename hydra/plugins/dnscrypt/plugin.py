"""
hydra/plugins/dnscrypt/plugin.py — DNSCrypt-proxy.

Устанавливает и настраивает DNSCrypt-proxy на 127.0.0.1:5300.
Sing-Box использует его как upstream DNS-сервер.
"""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.host import HOST
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
        required_commands=("systemctl",),
    )

    def install(self) -> bool:
        was_installed = self._installed()
        if not was_installed:
            if HOST.run(["apt-get", "update", "-qq"], timeout=60).returncode != 0:
                return False
            if HOST.run(
                ["apt-get", "install", "-y", "-qq", "dnscrypt-proxy"], timeout=60,
            ).returncode != 0:
                return False

        # Preserve an existing administrator/user configuration.  A freshly
        # installed distro config is replaced because HYDRA requires port 5300.
        if not was_installed or not DNSCRYPT_CONF.exists():
            self._write_default_config()
        service = HOST.run(["systemctl", "enable", "--now", "dnscrypt-proxy"])
        return service.returncode == 0

    def uninstall(self) -> bool:
        HOST.systemd("stop", "dnscrypt-proxy")
        HOST.systemd("disable", "dnscrypt-proxy")
        removed = HOST.run(
            ["apt-get", "remove", "-y", "-qq", "dnscrypt-proxy"], timeout=60,
        )
        if removed.returncode != 0:
            return False
        if DNSCRYPT_CONF.exists():
            DNSCRYPT_CONF.unlink(missing_ok=True)
        return True

    def repair_installation(self, *, enabled: bool) -> bool:
        """Reinstall the package while retaining HYDRA and user settings."""
        previous = DNSCRYPT_CONF.read_bytes() if DNSCRYPT_CONF.exists() else None
        repaired = HOST.run(
            ["apt-get", "install", "--reinstall", "-y", "-qq", "dnscrypt-proxy"],
            timeout=60,
        )
        if repaired.returncode != 0:
            if previous is not None:
                HOST.atomic_write(DNSCRYPT_CONF, previous)
            return False
        if previous is not None:
            HOST.atomic_write(DNSCRYPT_CONF, previous)
        else:
            self._write_default_config()
        action = [
            "systemctl", "enable" if enabled else "disable", "--now", "dnscrypt-proxy",
        ]
        return HOST.run(action).returncode == 0

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
            HOST.atomic_write(DNSCRYPT_CONF, config)
        if previous.get("running"):
            result = HOST.systemd("restart", "dnscrypt-proxy")
        else:
            result = HOST.systemd("stop", "dnscrypt-proxy")
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
        HOST.atomic_write(DNSCRYPT_CONF, conf)

    def configure(self, state: AppState) -> ConfigFragment:
        """Возвращает DNS-конфиг для Sing-Box."""
        dns_config = {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dnscrypt-local",
                    "server": "127.0.0.1",
                    "server_port": DNSCRYPT_PORT,
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
            r = HOST.systemd("is-active", "dnscrypt-proxy")
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
        enabled = HOST.systemd("enable", "dnscrypt-proxy")
        started = HOST.systemd("start", "dnscrypt-proxy")
        if enabled.returncode != 0 or started.returncode != 0:
            raise RuntimeError("Не удалось включить или запустить dnscrypt-proxy")

    def on_disable(self, state: AppState) -> None:
        state.network.dnscrypt_enabled = False
        stopped = HOST.systemd("stop", "dnscrypt-proxy")
        disabled = HOST.systemd("disable", "dnscrypt-proxy")
        if stopped.returncode != 0 or disabled.returncode != 0:
            raise RuntimeError("Не удалось остановить или отключить dnscrypt-proxy")
