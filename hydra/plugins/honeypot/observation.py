"""Runtime state, status, logs and traffic projections for Honeypot."""
from __future__ import annotations

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


class HoneypotObservationMixin:
    def status(self, state: PluginStateAccess | None=None) -> PluginStatus:
        result = self._honeypot_env().run(['systemctl', 'is-active', 'hydra-honeypot'], text=True)
        active = result.returncode == 0 and result.stdout.strip() == 'active'
        runtime_state = self._load_state()
        return PluginStatus(installed=self._honeypot_env().honeypot_script.exists(), enabled=active, running=active, port=runtime_state.get('port', self._honeypot_env().honeypot_port), info={'banned_ips': len(runtime_state.get('banned', {}))})

    def management_snapshot(self) -> dict:
        """Return plugin-owned configuration and evidence for management UI."""
        return self._honeypot_env().copy_module.deepcopy(self._load_state())

    def recent_logs(self, *, limit: int=30) -> list[str]:
        try:
            return self._honeypot_env().honeypot_log.read_text(encoding='utf-8', errors='replace').splitlines()[-max(1, min(int(limit), 200)):]
        except OSError:
            return []

    def _load_state(self) -> dict:
        default = {'banned': {}, 'port': self._honeypot_env().honeypot_port, 'whitelist': ['127.0.0.0/8', '::1/128']}
        if self._honeypot_env().honeypot_state.exists():
            try:
                loaded = self._honeypot_env().json_module.loads(self._honeypot_env().honeypot_state.read_text(encoding='utf-8'))
                loaded['whitelist'] = self._normalize_whitelist(loaded.get('whitelist', []))
                loaded.setdefault('banned', {})
                loaded.setdefault('port', self._honeypot_env().honeypot_port)
                return loaded
            except (OSError, self._honeypot_env().json_module.JSONDecodeError, TypeError):
                pass
        return default

    def banned_addresses(self) -> set[str]:
        """Return addresses currently owned by the Honeypot ban store."""
        banned = self._load_state().get('banned', {})
        return set(banned) if isinstance(banned, dict) else set()

    def _save_state(self, data: dict) -> None:
        self._honeypot_env().honeypot_state.parent.mkdir(parents=True, exist_ok=True)
        data['whitelist'] = self._normalize_whitelist(data.get('whitelist', []))
        temporary = self._honeypot_env().honeypot_state.with_name(f'.{self._honeypot_env().honeypot_state.name}.{self._honeypot_env().os_module.getpid()}.tmp')
        try:
            temporary.write_text(self._honeypot_env().json_module.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
            temporary.chmod(384)
            temporary.replace(self._honeypot_env().honeypot_state)
        finally:
            temporary.unlink(missing_ok=True)

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {}

