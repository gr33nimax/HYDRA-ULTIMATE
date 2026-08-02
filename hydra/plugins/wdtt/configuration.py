"""Desired configuration and user-facing contract methods for WDTT."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hydra.core.state_models import User
from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt import lifecycle, subscriptions


_MAX_SERVER_BINARY_SNAPSHOT = 64 * 1024 * 1024


@dataclass(frozen=True)
class WdttApplySnapshot:
    access_state: bytes | None
    server_binary: bytes | None
    server_revision: bytes | None


def _read_optional(path: Path, *, maximum_size: int | None = None) -> bytes | None:
    if not path.exists():
        return None
    if maximum_size is not None and path.stat().st_size > maximum_size:
        raise ValueError(f"WDTT runtime artifact is too large to snapshot: {path}")
    return path.read_bytes()


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
        self._pending_cfg = {
            'dtls_port': dtls_port,
            'wg_port': wg_port,
            'main_password': main_password,
            'admin_id': admin_id,
            'bot_token': bot_token,
            'passwords': passwords,
            'devices': devices,
            'access_state': subscriptions.build_access_state(state),
        }
        return ConfigFragment(nft_tproxy_ifaces=[self._wdtt_env().wg_interface])

    def apply(self, state: PluginStateAccess) -> bool:
        if not self._pending_cfg:
            return False
        # A pre-Hydra installation can leave a perfectly executable but
        # protocol-incompatible legacy binary in place. Revision-aware install
        # upgrades it before the service is restarted with subscription state.
        if not self.install():
            return False
        self._wdtt_env().config_dir.mkdir(parents=True, exist_ok=True)
        dtls_port = self._pending_cfg['dtls_port']
        wg_port = self._pending_cfg['wg_port']
        main_password = self._pending_cfg['main_password']
        admin_id = self._pending_cfg['admin_id']
        bot_token = self._pending_cfg['bot_token']
        passwords = self._pending_cfg['passwords']
        devices = self._pending_cfg['devices']
        access_state = self._pending_cfg['access_state']
        pw_data = {'main_password': main_password, 'admin_id': admin_id, 'bot_token': bot_token, 'passwords': passwords, 'devices': devices}
        self._wdtt_env().passwords_file.write_text(self._wdtt_env().json_module.dumps(pw_data, indent=2, ensure_ascii=False))
        self._wdtt_env().passwords_file.chmod(384)
        cfg = {'dtls_port': dtls_port, 'wg_port': wg_port, 'wg_subnet': self._wdtt_env().default_wg_subnet}
        self._wdtt_env().config_file.write_text(self._wdtt_env().json_module.dumps(cfg, indent=2))
        self._wdtt_env().config_file.chmod(384)
        access_content = self._wdtt_env().json_module.dumps(
            access_state,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ) + '\n'
        self._wdtt_env().host.atomic_write(
            self._wdtt_env().access_file,
            access_content,
            mode=0o600,
        )
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

    def snapshot(self, state: PluginStateAccess) -> WdttApplySnapshot:
        env = self._wdtt_env()
        return WdttApplySnapshot(
            access_state=subscriptions.access_snapshot(env),
            server_binary=_read_optional(
                env.bin_path,
                maximum_size=_MAX_SERVER_BINARY_SNAPSHOT,
            ),
            server_revision=_read_optional(lifecycle._server_revision_file(env)),
        )

    def rollback(
        self,
        state: PluginStateAccess,
        snapshot: WdttApplySnapshot,
    ) -> bool:
        env = self._wdtt_env()
        revision_file = lifecycle._server_revision_file(env)
        current_revision = _read_optional(revision_file)
        binary_restored = True
        if current_revision != snapshot.server_revision:
            try:
                if snapshot.server_binary is None:
                    env.host.remove_file(env.bin_path)
                else:
                    env.host.atomic_write(
                        env.bin_path,
                        snapshot.server_binary,
                        mode=0o755,
                    )
                if snapshot.server_revision is None:
                    env.host.remove_file(revision_file)
                else:
                    env.host.atomic_write(
                        revision_file,
                        snapshot.server_revision,
                        mode=0o600,
                    )
                action = "restart" if snapshot.server_binary is not None else "stop"
                binary_restored = env.host.run(
                    ["systemctl", action, env.service_name],
                    capture_output=True,
                ).returncode == 0
            except OSError:
                binary_restored = False
        access_restored = subscriptions.restore_access_snapshot(
            env,
            snapshot.access_state,
        )
        return binary_restored and access_restored

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
