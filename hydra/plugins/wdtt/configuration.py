"""Desired configuration and user-facing contract methods for WDTT."""
from __future__ import annotations

from pathlib import Path

from hydra.core.state_models import User
from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess


class WdttConfigurationMixin:
    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        ps = state.protocols.get(self.meta.name)
        cfg = ps.config if ps else {}
        dtls_port = cfg.get('dtls_port', self._wdtt_env().default_dtls_port)
        wg_port = cfg.get('wg_port', self._wdtt_env().default_wg_port)
        existing_data = {}
        if self._wdtt_env().passwords_file.exists():
            try:
                existing_data = self._wdtt_env().json_module.loads(self._wdtt_env().passwords_file.read_text())
            except Exception:
                pass
        main_password = cfg.get('main_password', existing_data.get('main_password', self._wdtt_env().system_password))
        admin_id = cfg.get('admin_id', existing_data.get('admin_id', ''))
        bot_token = cfg.get('bot_token', existing_data.get('bot_token', ''))
        passwords = existing_data.get('passwords', {})
        devices = existing_data.get('devices', {})
        self._pending_cfg = {'dtls_port': dtls_port, 'wg_port': wg_port, 'main_password': main_password, 'admin_id': admin_id, 'bot_token': bot_token, 'passwords': passwords, 'devices': devices}
        return ConfigFragment(nft_tproxy_ifaces=[self._wdtt_env().wg_interface])

    def apply(self, state: PluginStateAccess) -> bool:
        if not self._pending_cfg:
            return False
        self._wdtt_env().config_dir.mkdir(parents=True, exist_ok=True)
        dtls_port = self._pending_cfg['dtls_port']
        wg_port = self._pending_cfg['wg_port']
        main_password = self._pending_cfg['main_password']
        admin_id = self._pending_cfg['admin_id']
        bot_token = self._pending_cfg['bot_token']
        passwords = self._pending_cfg['passwords']
        devices = self._pending_cfg['devices']
        pw_data = {'main_password': main_password, 'admin_id': admin_id, 'bot_token': bot_token, 'passwords': passwords, 'devices': devices}
        self._wdtt_env().passwords_file.write_text(self._wdtt_env().json_module.dumps(pw_data, indent=2, ensure_ascii=False))
        self._wdtt_env().passwords_file.chmod(384)
        cfg = {'dtls_port': dtls_port, 'wg_port': wg_port, 'wg_subnet': self._wdtt_env().default_wg_subnet}
        self._wdtt_env().config_file.write_text(self._wdtt_env().json_module.dumps(cfg, indent=2))
        self._wdtt_env().config_file.chmod(384)
        self._install_service(dtls_port, wg_port, main_password, admin_id, bot_token)
        self._wdtt_env().host.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True)
        sysctl = Path('/etc/sysctl.d/99-wdtt.conf')
        sysctl.write_text('net.ipv4.ip_forward = 1\n')
        self._fw_open_udp(dtls_port)
        self._add_masquerade()
        self._wdtt_env().host.run(['systemctl', 'daemon-reload'], capture_output=True)
        self._wdtt_env().host.run(['systemctl', 'reload-or-restart', self._wdtt_env().service_name], capture_output=True)
        self._wdtt_env().time_module.sleep(2)
        return True

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        return ''

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        return ''
