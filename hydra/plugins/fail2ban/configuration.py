"""Desired jail policy and configuration rendering for Fail2ban."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.fail2ban.model import Fail2banEnvironment

def _filters(env: Fail2banEnvironment) -> dict[str, str]:
    return {}

def _valid_whitelist(env: Fail2banEnvironment, state: PluginStateAccess | None) -> list[str]:
    result = ['127.0.0.1/8', '::1']
    ssh_connection = env.os_module.environ.get('SSH_CONNECTION', '').split()
    candidates: list[object] = []
    if ssh_connection:
        candidates.append(ssh_connection[0])
    if state is not None:
        candidates.extend(env.host_ip_addresses((state.network.server_ip,)))
        configured = env.get_protocol(state, 'fail2ban').config.get('whitelist', [])
        if isinstance(configured, list):
            candidates.extend(configured)
    else:
        candidates.extend(env.host_ip_addresses())
    for value in candidates:
        try:
            normalized = str(env.ipaddress_module.ip_network(str(value), strict=False)) if '/' in str(value) else str(env.ipaddress_module.ip_address(str(value)))
        except ValueError:
            continue
        if normalized not in result:
            result.append(normalized)
    return result



class Fail2banConfigurationMixin:
    def jail_options(self, state: PluginStateAccess | None) -> dict[str, dict[str, str]]:
        jails: dict[str, dict[str, str]] = {'hydra-sshd': {'enabled': 'true', 'filter': 'sshd', 'backend': 'systemd', 'maxretry': '5', 'findtime': '600', 'bantime': '3600'}, 'hydra-recidive': {'enabled': str(self._fail2ban_env().f2b_log.exists()).lower(), 'filter': 'recidive', 'logpath': str(self._fail2ban_env().f2b_log), 'maxretry': '3', 'findtime': '86400', 'bantime': '604800', 'banaction': '%(banaction_allports)s'}}
        if state is not None:
            config = self._fail2ban_env().get_protocol(state, 'fail2ban').config
            overrides = config.get('jails', {})
            if isinstance(overrides, dict):
                for jail, values in overrides.items():
                    if jail not in jails or not isinstance(values, dict):
                        continue
                    for option, value in values.items():
                        if option == 'enabled' and isinstance(value, bool):
                            jails[jail][option] = str(value).lower()
                        elif option in {'bantime', 'findtime', 'maxretry'}:
                            candidate = str(value)
                            if candidate.isdigit() and int(candidate) > 0:
                                jails[jail][option] = candidate
        return jails

    def set_jail_options(self, *, state: PluginStateAccess, jail: str, bantime: str, findtime: str, maxretry: str) -> bool:
        """Update one supported jail through the desired-state contract."""
        if jail not in self.jail_options(state):
            raise ValueError(f'unsupported fail2ban jail: {jail}')
        values = {'bantime': str(bantime), 'findtime': str(findtime), 'maxretry': str(maxretry)}
        if any((not value.isdigit() or int(value) < 1 for value in values.values())):
            raise ValueError('jail timing values must be positive integers')
        config = self._fail2ban_env().get_protocol(state, 'fail2ban').config
        current = config.setdefault('jails', {}).setdefault(jail, {})
        if all((current.get(key) == value for key, value in values.items())):
            return False
        current.update(values)
        return True

    def set_jail_enabled(self, *, state: PluginStateAccess, jail: str, enabled: bool) -> bool:
        """Enable or disable one supported jail in desired state."""
        if jail not in self.jail_options(state):
            raise ValueError(f'unsupported fail2ban jail: {jail}')
        config = self._fail2ban_env().get_protocol(state, 'fail2ban').config
        current = config.setdefault('jails', {}).setdefault(jail, {})
        value = bool(enabled)
        if current.get('enabled') is value:
            return False
        current['enabled'] = value
        return True

    def add_whitelist(self, *, state: PluginStateAccess, network: str) -> bool:
        """Add a validated address or network to desired state."""
        normalized = str(self._fail2ban_env().ipaddress_module.ip_network(network, strict=False)) if '/' in network else str(self._fail2ban_env().ipaddress_module.ip_address(network))
        values = self._fail2ban_env().get_protocol(state, 'fail2ban').config.setdefault('whitelist', [])
        if normalized in values:
            return False
        values.append(normalized)
        return True

    def remove_whitelist(self, *, state: PluginStateAccess, network: str) -> bool:
        """Remove one address or network from desired state."""
        values = self._fail2ban_env().get_protocol(state, 'fail2ban').config.setdefault('whitelist', [])
        if network not in values:
            return False
        values.remove(network)
        return True

    def reset_jails(self, *, state: PluginStateAccess) -> bool:
        """Drop custom jail overrides; the next apply restores defaults."""
        config = self._fail2ban_env().get_protocol(state, 'fail2ban').config
        config.pop('jails', None)
        return True

    def _write_jails(self, state: PluginStateAccess | None=None) -> bool:
        self.last_error = ''
        self._fail2ban_env().jail_dir.mkdir(parents=True, exist_ok=True)
        self._fail2ban_env().filter_dir.mkdir(parents=True, exist_ok=True)
        contents: dict[Path, str] = {self._fail2ban_env().jail_dir / '00-hydra-defaults.local': f"[DEFAULT]\nignoreip = {' '.join(self._valid_whitelist(state))}\n", self._fail2ban_env().jail_dir / 'zz-hydra-disable-default-sshd.local': '[sshd]\nenabled = false\n'}
        for name, content in self._filters().items():
            contents[self._fail2ban_env().filter_dir / f'{name}.conf'] = content
        jail_options = self.jail_options(state)
        for name, options in jail_options.items():
            body = '\n'.join((f'{key} = {value}' for key, value in options.items()))
            contents[self._fail2ban_env().jail_dir / f'{name}.local'] = f'[{name}]\n{body}\n'
        obsolete_paths = tuple((self._fail2ban_env().jail_dir / f'{name}.local' for name in ('hydra-anytls', 'hydra-trusttunnel', 'hydra-trusttunnel-quic', 'hydra-naive', 'hydra-singbox', 'hydra-mieru', 'hydra-portscan'))) + tuple((self._fail2ban_env().filter_dir / f'{name}.conf' for name in ('hydra-anytls', 'hydra-trusttunnel', 'hydra-trusttunnel-quic', 'hydra-naive', 'sing-box', 'awg-invalid', 'hydra-mieru', 'hydra-portscan')))
        backups: dict[Path, bytes | None] = {}
        try:
            for path, content in contents.items():
                backups[path] = path.read_bytes() if path.exists() else None
                self._fail2ban_env().atomic_write(path, content)
            for path in obsolete_paths:
                if path not in backups:
                    backups[path] = path.read_bytes() if path.exists() else None
                path.unlink(missing_ok=True)
            client = self._fail2ban_env().shutil_module.which('fail2ban-client') or str(self._fail2ban_env().f2b_bin)
            check = self._fail2ban_env().run([client, '-t'], timeout=30, text=True)
            if check.returncode != 0:
                raise RuntimeError(check.stderr or check.stdout or 'fail2ban configuration test failed')
        except Exception as exc:
            self.last_error = ' '.join(str(exc).split())[:600]
            for path, original in backups.items():
                try:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        temporary = path.with_name(f'.{path.name}.{self._fail2ban_env().os_module.getpid()}.rollback')
                        temporary.write_bytes(original)
                        temporary.replace(path)
                except OSError:
                    pass
            return False
        legacy_sshd = self._fail2ban_env().jail_dir / 'sshd.local'
        try:
            if legacy_sshd.read_text(encoding='utf-8') == '[sshd]\nenabled = false\n':
                legacy_sshd.unlink()
        except OSError:
            pass
        if state is not None:
            config = self._fail2ban_env().get_protocol(state, 'fail2ban').config
            overrides = config.get('jails')
            if isinstance(overrides, dict):
                for name in ('hydra-anytls', 'hydra-trusttunnel', 'hydra-trusttunnel-quic', 'hydra-naive', 'hydra-mieru', 'hydra-awg', 'hydra-portscan'):
                    overrides.pop(name, None)
                if not overrides:
                    config.pop('jails', None)
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        return ConfigFragment()

    def restore_defaults(self, state: PluginStateAccess) -> bool:
        """Restore generated jail defaults without changing service state."""
        if not self._installed():
            self.last_error = 'fail2ban-client не найден'
            return False
        protocol = self._fail2ban_env().get_protocol(state, 'fail2ban')
        marker = object()
        previous_jails = protocol.config.pop('jails', marker)
        was_running = self.status().running
        if not self._write_jails(state):
            if previous_jails is not marker:
                protocol.config['jails'] = previous_jails
            return False
        applied = self._cleanup_legacy_awg_debug()
        if applied:
            applied = self._remove_legacy_portscan_rule()
            if not applied:
                self.last_error = 'Не удалось удалить устаревшее правило portscan из iptables'
        if applied and was_running:
            reload_result = self._fail2ban_env().run(['fail2ban-client', 'reload'], timeout=20)
            if reload_result.returncode != 0 or not self.status().running:
                restart = self._fail2ban_env().run(['systemctl', 'restart', 'fail2ban'], timeout=30)
                applied = restart.returncode == 0 and self.status().running
                if not applied:
                    detail = restart.stderr or restart.stdout or 'служба не перешла в active'
                    self.last_error = ' '.join(str(detail).split())[:600]
            else:
                applied = True
        if applied:
            return True
        if previous_jails is not marker:
            protocol.config['jails'] = previous_jails
        self._write_jails(state)
        self._cleanup_legacy_awg_debug()
        if was_running:
            self._fail2ban_env().run(['fail2ban-client', 'reload'], timeout=20)
        return False

    def apply(self, state: PluginStateAccess) -> bool:
        if not self._installed() or not self._write_jails(state):
            return False
        if not self._cleanup_legacy_awg_debug():
            return False
        if not self._remove_legacy_portscan_rule():
            return False
        reload_result = self._fail2ban_env().run(['fail2ban-client', 'reload'], timeout=20)
        if reload_result.returncode != 0 or not self.status().running:
            restart = self._fail2ban_env().run(['systemctl', 'restart', 'fail2ban'], timeout=30)
            if restart.returncode != 0:
                return False
        return self.status().running

