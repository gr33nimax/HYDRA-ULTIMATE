"""Read-only status, logs and traffic projections for Fail2ban."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.fail2ban.model import Fail2banEnvironment

def clear_logs(env: Fail2banEnvironment) -> tuple[bool, str]:
    """Truncate Fail2ban logs without exposing host paths to the UI."""
    cleared: list[str] = []
    errors: list[str] = []
    for path in (env.f2b_log, Path(f'{env.f2b_log}.1')):
        if not path.exists():
            continue
        try:
            env.host.atomic_write(path, '')
            cleared.append(str(path))
        except Exception as exc:
            errors.append(f'{path.name}: {exc}')
    if errors:
        return (False, '; '.join(errors))
    if not cleared:
        return (True, 'Лог-файлы не найдены')
    return (True, f"Очищено: {', '.join(cleared)}")



class Fail2banObservationMixin:
    def status(self, state: PluginStateAccess | None=None) -> PluginStatus:
        installed = self._installed()
        running = False
        banned = 0
        if installed:
            active = self._fail2ban_env().run(['systemctl', 'is-active', 'fail2ban'], text=True)
            running = active.returncode == 0 and active.stdout.strip() == 'active'
            if running:
                overall = self._fail2ban_env().run(['fail2ban-client', 'status'], timeout=10, text=True)
                match = self._fail2ban_env().re_module.search('Jail list:\\s*(.*)', overall.stdout)
                if match:
                    for jail in (item.strip() for item in match.group(1).split(',')):
                        if not jail:
                            continue
                        detail = self._fail2ban_env().run(['fail2ban-client', 'status', jail], timeout=10, text=True)
                        current = self._fail2ban_env().re_module.search('Currently banned:\\s*(\\d+)', detail.stdout)
                        if current:
                            banned += int(current.group(1))
        return PluginStatus(installed=installed, enabled=running, running=running, info={'banned_ips': banned})

    def recent_logs(self, *, limit: int=5000) -> list[str]:
        """Return recent Fail2ban records without leaking its log path."""
        bounded = max(1, min(int(limit), 10000))
        try:
            lines = self._fail2ban_env().f2b_log.read_text(encoding='utf-8', errors='replace').splitlines()
            if lines:
                return lines[-bounded:]
        except OSError:
            pass
        result = self._fail2ban_env().run(['journalctl', '-u', 'fail2ban', '-n', str(bounded), '--no-pager', '-o', 'short-iso'], timeout=15, text=True)
        return str(result.stdout or '').splitlines()

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {}

