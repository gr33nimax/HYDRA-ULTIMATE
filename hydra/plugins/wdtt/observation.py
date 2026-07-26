"""Runtime observation, management projections and traffic for WDTT."""
from __future__ import annotations

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt.model import (
    WdttEnvironment,
    WdttRuntimeObservation,
)

def password_registry(env: WdttEnvironment) -> dict:
    """Return a detached snapshot of the WDTT password registry."""
    empty = {'main_password': '', 'admin_id': '', 'bot_token': '', 'passwords': {}, 'devices': {}}
    if not env.passwords_file.exists():
        return empty
    try:
        data = env.json_module.loads(env.passwords_file.read_text(encoding='utf-8'))
    except (OSError, TypeError, ValueError, env.json_module.JSONDecodeError):
        return empty
    return data if isinstance(data, dict) else empty

def save_password_registry(env: WdttEnvironment, *, data: dict) -> bool:
    """Persist the complete registry atomically with private permissions."""
    if not isinstance(data, dict):
        raise TypeError('WDTT password registry must be a dictionary')
    env.config_dir.mkdir(parents=True, exist_ok=True)
    env.host.atomic_write(env.passwords_file, env.json_module.dumps(data, indent=2, ensure_ascii=False), mode=384)
    return True

def hot_reload(env: WdttEnvironment) -> bool:
    """Ask the running WDTT process to reload its password registry."""
    result = env.host.run(['pidof', 'wdtt-server'], capture_output=True, text=True)
    pids = result.stdout.split()
    if not pids:
        return False
    return env.host.run(['kill', '-HUP', *pids], capture_output=True).returncode == 0

def public_server_ip(env: WdttEnvironment) -> str:
    """Resolve the same preferred server address used by legacy links."""
    address = env.local_ip()
    if address and (not address.startswith('127.')) and (address != '::1'):
        return address
    address = env.public_ip()
    if address and (not address.startswith('127.')) and (address != '::1'):
        return address
    return 'ВАШ_IP'

def save_client_link(env: WdttEnvironment, *, link: str, filename: str) -> str:
    """Save one generated qwdtt link inside the managed config directory."""
    if not env.re_module.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', filename) or '..' in filename or (not filename.endswith('.txt')):
        raise ValueError('invalid WDTT client-link filename')
    env.config_dir.mkdir(parents=True, exist_ok=True)
    path = env.config_dir / filename
    env.host.atomic_write(path, f'{link}\n', mode=384)
    return str(path)



class WdttObservationMixin:
    def observe_runtime(self) -> WdttRuntimeObservation:
        """Read host facts without changing desired state."""
        installed = self._installed()
        running = False
        if installed:
            r = self._wdtt_env().host.run(['systemctl', 'is-active', self._wdtt_env().service_name], capture_output=True, text=True)
            running = r.stdout.strip() == 'active'
        dtls_port = self._wdtt_env().default_dtls_port
        wg_port = self._wdtt_env().default_wg_port
        if self._wdtt_env().config_file.exists():
            try:
                cfg_data = self._wdtt_env().json_module.loads(self._wdtt_env().config_file.read_text())
                dtls_port = int(cfg_data.get('dtls_port', self._wdtt_env().default_dtls_port))
                wg_port = int(cfg_data.get('wg_port', self._wdtt_env().default_wg_port))
            except Exception:
                pass
        main_password = self._wdtt_env().system_password
        admin_id = ''
        bot_token = ''
        if self._wdtt_env().passwords_file.exists():
            try:
                pw_data = self._wdtt_env().json_module.loads(self._wdtt_env().passwords_file.read_text())
                main_password = str(pw_data.get('main_password', self._wdtt_env().system_password))
                admin_id = str(pw_data.get('admin_id', ''))
                bot_token = str(pw_data.get('bot_token', ''))
            except Exception:
                pass
        return WdttRuntimeObservation(installed=installed, running=running, dtls_port=dtls_port, wg_port=wg_port, main_password=main_password, admin_id=admin_id, bot_token=bot_token)

    def status(self, state: PluginStateAccess | None=None) -> PluginStatus:
        runtime = self.observe_runtime()
        return PluginStatus(installed=runtime.installed, enabled=self._wdtt_env().service_file.exists(), running=runtime.running, port=runtime.dtls_port)

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {}

    def total_traffic(self, state: PluginStateAccess | None=None) -> int | None:
        """Возвращает общий RX+TX интерфейса без ложной per-user атрибуции."""
        try:
            rx = int((self._wdtt_env().wg_stats_dir / 'rx_bytes').read_text().strip())
            tx = int((self._wdtt_env().wg_stats_dir / 'tx_bytes').read_text().strip())
            return max(0, rx) + max(0, tx)
        except (OSError, TypeError, ValueError):
            return None

    def aggregate_traffic_snapshot(self, state: PluginStateAccess) -> int | None:
        """Expose the resettable interface total without fake attribution."""
        return self.total_traffic(state)

    def connected_clients(self, state: PluginStateAccess | None=None) -> list[dict]:
        return []
