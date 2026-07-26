"""Install, rollback and cleanup runtime operations for Fail2ban."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.context import PluginStateAccess
from hydra.plugins.fail2ban.model import Fail2banEnvironment

def _remove_owned_configuration(env: Fail2banEnvironment) -> None:
    (env.jail_dir / '00-hydra-defaults.local').unlink(missing_ok=True)
    (env.jail_dir / 'zz-hydra-disable-default-sshd.local').unlink(missing_ok=True)
    for name in env.owned_jails:
        (env.jail_dir / f'{name}.local').unlink(missing_ok=True)
    for name in env.owned_filters:
        (env.filter_dir / f'{name}.conf').unlink(missing_ok=True)
    legacy_sshd = env.jail_dir / 'sshd.local'
    try:
        if legacy_sshd.read_text(encoding='utf-8') == '[sshd]\nenabled = false\n':
            legacy_sshd.unlink()
    except OSError:
        pass

def _awg_dynamic_debug_control(env: Fail2banEnvironment) -> Path | None:
    return next((path for path in env.awg_dynamic_debug_paths if path.exists()), None)

def _remove_legacy_portscan_rule(env: Fail2banEnvironment) -> bool:
    """Remove the pre-AntiDPI port-scan LOG rule during upgrades."""
    if env.shutil_module.which('iptables') is None:
        return True
    check = env.run(['iptables', '-C', 'INPUT', *env.portscan_rule])
    for _ in range(32):
        if check.returncode != 0:
            return True
        if env.run(['iptables', '-D', 'INPUT', *env.portscan_rule]).returncode != 0:
            return False
        check = env.run(['iptables', '-C', 'INPUT', *env.portscan_rule])
    return True



class Fail2banRuntimeMixin:
    def install(self) -> bool:
        if not self._installed():
            update = self._fail2ban_env().run(['apt-get', 'update', '-qq'], timeout=180)
            if update.returncode != 0:
                return False
            install = self._fail2ban_env().run(['apt-get', 'install', '-y', '-qq', 'fail2ban'], timeout=180)
            if install.returncode != 0 or not self._installed():
                return False
        if not self._write_jails(None):
            return False
        if not self._remove_legacy_portscan_rule():
            return False
        enabled = self._fail2ban_env().run(['systemctl', 'enable', '--now', 'fail2ban'])
        return enabled.returncode == 0 and self.status().running

    def uninstall(self) -> bool:
        if not self._cleanup_legacy_awg_debug():
            return False
        if not self._remove_legacy_portscan_rule():
            return False
        self._fail2ban_env().run(['systemctl', 'disable', '--now', 'fail2ban'])
        self._remove_owned_configuration()
        removed = self._fail2ban_env().run(['apt-get', 'remove', '-y', '-qq', 'fail2ban'], timeout=120)
        return removed.returncode == 0 or not self._installed()

    def _installed(self) -> bool:
        return self._fail2ban_env().f2b_bin.exists() or self._fail2ban_env().shutil_module.which('fail2ban-client') is not None

    def _cleanup_legacy_awg_debug(self) -> bool:
        """Remove the obsolete Fail2ban AWG debug owner without fighting AntiDPI."""
        control = self._awg_dynamic_debug_control()
        if control is None and (not self._fail2ban_env().awg_debug_service.exists()):
            return True
        if control is not None:
            try:
                control.write_text('\n'.join((f'module amneziawg func {function} -p' for function in self._fail2ban_env().awg_legacy_noisy_debug_functions)) + '\n', encoding='utf-8')
            except OSError as exc:
                self.last_error = f'Не удалось убрать legacy AmneziaWG debug: {exc}'
                return False
        self._fail2ban_env().run(['systemctl', 'disable', '--now', 'hydra-awg-fail2ban-debug.service'])
        self._fail2ban_env().awg_debug_service.unlink(missing_ok=True)
        self._fail2ban_env().run(['systemctl', 'daemon-reload'])
        if self._fail2ban_env().antidpi_awg_debug_service.exists():
            self._fail2ban_env().run(['systemctl', 'try-restart', 'hydra-awg-antidpi-debug.service'])
        return True

    def snapshot(self, state: PluginStateAccess):

        def collect(directory: Path, prefixes: tuple[str, ...]):
            result = {}
            if directory.exists():
                for path in directory.iterdir():
                    if path.is_file() and path.name.startswith(prefixes):
                        result[str(path)] = path.read_bytes()
            return result
        return {'jails': collect(self._fail2ban_env().jail_dir, self._fail2ban_env().owned_jails), 'filters': collect(self._fail2ban_env().filter_dir, self._fail2ban_env().owned_filters), 'awg_service': self._fail2ban_env().awg_debug_service.read_bytes() if self._fail2ban_env().awg_debug_service.exists() else None, 'running': self.status().running}

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        previous = snapshot or {}
        for directory, key, prefixes in ((self._fail2ban_env().jail_dir, 'jails', self._fail2ban_env().owned_jails), (self._fail2ban_env().filter_dir, 'filters', self._fail2ban_env().owned_filters)):
            directory.mkdir(parents=True, exist_ok=True)
            for path in directory.iterdir():
                if path.is_file() and path.name.startswith(prefixes):
                    path.unlink(missing_ok=True)
            for name, content in previous.get(key, {}).items():
                path = Path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        service = previous.get('awg_service')
        if service is None:
            self._fail2ban_env().awg_debug_service.unlink(missing_ok=True)
        else:
            self._fail2ban_env().awg_debug_service.parent.mkdir(parents=True, exist_ok=True)
            self._fail2ban_env().awg_debug_service.write_bytes(service)
        result = self._fail2ban_env().run(['fail2ban-client', 'reload'], timeout=20) if previous.get('running') else self._fail2ban_env().run(['systemctl', 'stop', 'fail2ban'])
        return result.returncode == 0

    def on_enable(self, state: PluginStateAccess) -> None:
        """Central apply renders the effective runtime whitelist."""

    def on_disable(self, state: PluginStateAccess) -> None:
        if not self._cleanup_legacy_awg_debug():
            raise RuntimeError('AmneziaWG dynamic debug could not be disabled')
        if not self._remove_legacy_portscan_rule():
            raise RuntimeError('Fail2ban port-scan log rule could not be removed')
        stopped = self._fail2ban_env().run(['systemctl', 'stop', 'fail2ban'])
        if stopped.returncode != 0:
            raise RuntimeError('Fail2ban could not be stopped')
