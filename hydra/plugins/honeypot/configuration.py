"""Desired-state commands, snapshots and normalization for Honeypot."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.honeypot.model import HoneypotEnvironment

def _normalize_whitelist(env: HoneypotEnvironment, values: list[object]) -> list[str]:
    result = ['127.0.0.0/8', '::1/128']
    for value in values:
        try:
            network = env.ipaddress_module.ip_network(str(value), strict=False)
        except ValueError:
            try:
                address = env.ipaddress_module.ip_address(str(value))
                network = env.ipaddress_module.ip_network(f'{address}/{address.max_prefixlen}')
            except ValueError:
                continue
        normalized = str(network)
        if normalized not in result:
            result.append(normalized)
    return result



class HoneypotConfigurationMixin:
    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        return ConfigFragment()

    def snapshot(self, state: PluginStateAccess):

        def read(path: Path):
            return path.read_bytes() if path.exists() else None
        return {'script': read(self._honeypot_env().honeypot_script), 'service': read(self._honeypot_env().honeypot_service), 'state': read(self._honeypot_env().honeypot_state), 'running': self.status().running}

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        previous = snapshot or {}
        for key, path in (('script', self._honeypot_env().honeypot_script), ('service', self._honeypot_env().honeypot_service), ('state', self._honeypot_env().honeypot_state)):
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(path.suffix + '.rollback')
                tmp.write_bytes(content)
                tmp.replace(path)
        if previous.get('running'):
            result = self._honeypot_env().run(['systemctl', 'restart', 'hydra-honeypot'])
        else:
            result = self._honeypot_env().run(['systemctl', 'stop', 'hydra-honeypot'])
        return result.returncode == 0

    def _sync_host_whitelist(self, config: dict, state: PluginStateAccess) -> list[str]:
        """Persist all VPS addresses before generating the honeypot service."""
        current = config.get('whitelist', [])
        if not isinstance(current, list):
            current = []
        effective = self._normalize_whitelist([*current, *self._honeypot_env().host_ip_addresses((state.network.server_ip,))])
        if effective != current:
            config['whitelist'] = effective
            self._save_state(config)
        return effective

    def set_port(self, *, state: PluginStateAccess, port: int) -> bool:
        port = int(port)
        if not 1 <= port <= 65535:
            return False
        for name, protocol in state.protocols.items():
            if name != self.meta.name and protocol.enabled and (protocol.port == port):
                return False
        config = self._load_state()
        if int(config.get('port', self._honeypot_env().honeypot_port)) == port:
            return False
        config['port'] = port
        self._save_state(config)
        return True

    def add_whitelist(self, *, state: PluginStateAccess, network: str) -> bool:
        normalized = str(self._honeypot_env().ipaddress_module.ip_network(network, strict=False))
        config = self._load_state()
        values = self._normalize_whitelist(config.get('whitelist', []))
        if normalized in values:
            return False
        values.append(normalized)
        config['whitelist'] = values
        self._save_state(config)
        return True

    def remove_whitelist(self, *, state: PluginStateAccess, network: str) -> bool:
        normalized = str(self._honeypot_env().ipaddress_module.ip_network(network, strict=False))
        config = self._load_state()
        values = self._normalize_whitelist(config.get('whitelist', []))
        if normalized not in values:
            return False
        values.remove(normalized)
        config['whitelist'] = values
        self._save_state(config)
        return True

    def unban_address(self, *, state: PluginStateAccess, address: str) -> bool:
        return self.unban(address)
