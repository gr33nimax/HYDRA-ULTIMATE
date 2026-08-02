"""Service lifecycle, systemd and firewall operations for WDTT."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt import headless
from hydra.plugins.wdtt.model import WdttEnvironment

def _derive_password(uuid: str) -> str:
    from hydra.utils.crypto import derive_key
    return derive_key('wdtt-pass', uuid)

def _installed(env: WdttEnvironment) -> bool:
    return env.bin_path.exists()


def _server_revision_file(env: WdttEnvironment) -> Path:
    return env.config_dir / "server-revision"


def _server_revision_current(env: WdttEnvironment) -> bool:
    if not _installed(env):
        return False
    try:
        return (
            _server_revision_file(env).read_text(encoding="ascii").strip()
            == env.source_revision
        )
    except (OSError, UnicodeError):
        # Existing installations predate revision tracking and may still run
        # the legacy WDTT binary, which cannot decrypt Hydra device grants.
        return False


def _record_server_revision(env: WdttEnvironment) -> None:
    env.config_dir.mkdir(parents=True, exist_ok=True)
    env.host.atomic_write(
        _server_revision_file(env),
        f"{env.source_revision}\n",
        mode=0o600,
    )

def _install_service(
    env: WdttEnvironment,
    dtls_port: int,
    wg_port: int,
    main_password: str,
    admin_id: str,
    bot_token: str,
) -> None:
    env.service_file.write_text(f'[Unit]\nDescription=qWDTT — WireGuard over VK TURN\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={env.bin_path} -config-dir {env.config_dir} -password {main_password} -listen 0.0.0.0:{dtls_port} -wg-port {wg_port} ' + (f'-admin {admin_id} ' if admin_id else '') + (f'-bot-token {bot_token} ' if bot_token else '') + '\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n')
    env.host.run(['systemctl', 'daemon-reload'], capture_output=True)
    env.host.run(['systemctl', 'enable', env.service_name], capture_output=True)

def _fw_tool(env: WdttEnvironment) -> str:
    if env.shutil_module.which('ufw'):
        r = env.host.run(['ufw', 'status'], capture_output=True, text=True)
        if 'Status: active' in r.stdout:
            return 'ufw'
    return 'iptables'

def _masquerade_exists(env: WdttEnvironment) -> bool:
    r = env.host.run(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-s', env.default_wg_subnet, '!', '-d', env.default_wg_subnet, '-j', 'MASQUERADE'], capture_output=True)
    return r.returncode == 0

def _ipt_persist(env: WdttEnvironment, self=None) -> None:
    env.firewall_module.persist()



class WdttLifecycleMixin:
    def install(self) -> bool:
        env = self._wdtt_env()
        if _server_revision_current(env):
            return True
        if self._installed():
            print('  Обновление legacy wdtt-server до Hydra-ревизии...')
        else:
            print('  Сборка wdtt-server из исходников...')
        if not self._build_wdtt_server():
            print('  Не удалось собрать wdtt-server.')
            return False
        _record_server_revision(env)
        return _server_revision_current(env)

    def uninstall(self) -> bool:
        headless.uninstall(self._wdtt_env())
        dtls_port = self._wdtt_env().default_dtls_port
        if self._wdtt_env().config_file.exists():
            try:
                dtls_port = int(self._wdtt_env().json_module.loads(self._wdtt_env().config_file.read_text(encoding='utf-8')).get('dtls_port', self._wdtt_env().default_dtls_port))
            except (OSError, ValueError, TypeError, self._wdtt_env().json_module.JSONDecodeError):
                pass
        self._wdtt_env().host.run(['systemctl', 'stop', self._wdtt_env().service_name], capture_output=True)
        self._wdtt_env().host.run(['systemctl', 'disable', self._wdtt_env().service_name], capture_output=True)
        if self._wdtt_env().service_file.exists():
            self._wdtt_env().service_file.unlink()
        self._wdtt_env().host.run(['systemctl', 'daemon-reload'], capture_output=True)
        self._wdtt_env().host.run(['systemctl', 'reset-failed'], capture_output=True)
        if self._wdtt_env().bin_path.exists():
            self._wdtt_env().bin_path.unlink()
        self._fw_close_udp(dtls_port)
        self._remove_masquerade()
        sysctl = Path('/etc/sysctl.d/99-wdtt.conf')
        if sysctl.exists():
            sysctl.unlink()
        if self._wdtt_env().config_dir.exists():
            self._wdtt_env().shutil_module.rmtree(self._wdtt_env().config_dir, ignore_errors=True)
        return True

    def on_enable(self, state: PluginStateAccess) -> None:
        """Central apply prepares configuration and starts the service."""

    def on_disable(self, state: PluginStateAccess) -> None:
        self._wdtt_env().host.run(['systemctl', 'stop', self._wdtt_env().service_name], capture_output=True)

    def _fw_open_udp(self, port: int) -> None:
        if self._fw_tool() == 'ufw':
            r = self._wdtt_env().host.run(['ufw', 'status'], capture_output=True, text=True)
            if not self._wdtt_env().re_module.search(f'^{port}/udp\\b.*ALLOW', r.stdout, self._wdtt_env().re_module.MULTILINE):
                self._wdtt_env().host.run(['ufw', 'allow', f'{port}/udp', 'comment', 'qWDTT DTLS'], capture_output=True)
            return
        args = ['-p', 'udp', '--dport', str(port), '-j', 'ACCEPT']
        r = self._wdtt_env().host.run(['iptables', '-t', 'filter', '-C', 'INPUT'] + args, capture_output=True)
        if r.returncode != 0:
            self._wdtt_env().host.run(['iptables', '-t', 'filter', '-I', 'INPUT', '1'] + args, capture_output=True)
            self._ipt_persist()

    def _fw_close_udp(self, port: int) -> None:
        if self._wdtt_env().shutil_module.which('ufw'):
            self._wdtt_env().host.run(['ufw', 'delete', 'allow', f'{port}/udp'], capture_output=True)
        args = ['-p', 'udp', '--dport', str(port), '-j', 'ACCEPT']
        for _ in range(5):
            r = self._wdtt_env().host.run(['iptables', '-t', 'filter', '-C', 'INPUT'] + args, capture_output=True)
            if r.returncode != 0:
                break
            self._wdtt_env().host.run(['iptables', '-t', 'filter', '-D', 'INPUT'] + args, capture_output=True)
        self._ipt_persist()

    def _add_masquerade(self) -> None:
        if not self._masquerade_exists():
            self._wdtt_env().host.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', self._wdtt_env().default_wg_subnet, '!', '-d', self._wdtt_env().default_wg_subnet, '-j', 'MASQUERADE'], capture_output=True)
            self._ipt_persist()

    def _remove_masquerade(self) -> None:
        for _ in range(3):
            if not self._masquerade_exists():
                break
            self._wdtt_env().host.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-s', self._wdtt_env().default_wg_subnet, '!', '-d', self._wdtt_env().default_wg_subnet, '-j', 'MASQUERADE'], capture_output=True)
        self._ipt_persist()
