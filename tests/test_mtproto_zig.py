from hydra.core.state import AppState, PluginState, User
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from hydra.plugins.mtproto_zig import configuration, installation, observation, runtime
from hydra.plugins.mtproto_zig.credentials import derive_secret, derive_username
from hydra.plugins.telemt.credentials import derive_secret as telemt_secret
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin


def state(*, shadow=False):
    result = AppState(users=[User(email="a@example", uuid="user-a")])
    result.network.server_ip = "203.0.113.10"
    result.protocols["mtproto_zig"] = PluginState(
        enabled=True, config={"domain": "cover.example", "_tls_passthrough_route": configuration.route_metadata()}
    )
    if shadow:
        result.protocols["shadowtls"] = PluginState(enabled=True, config={"handshake_sni": "shadow.example"})
    return result


def test_config_uses_direct_then_sni_loopback_and_public_link():
    plugin = MtprotoZigPlugin()
    direct = state()
    plugin.configure(direct)
    assert plugin._pending_config is not None
    assert 'bind_address = "::"' in plugin._pending_config
    assert "port = 443" in plugin._pending_config
    mux = state(shadow=True)
    plugin.configure(mux)
    assert plugin._pending_config is not None
    assert 'bind_address = "127.0.0.1"' in plugin._pending_config
    assert "port = 20449" in plugin._pending_config
    assert "&port=443&secret=ee" in plugin.client_link(mux.users[0], mux)


def test_credentials_are_isolated_from_telemt():
    assert derive_secret("same") != telemt_secret("same")


def test_base64_user_keys_are_quoted_for_toml():
    """A derived username may contain +, / or =; an unquoted key is invalid TOML."""
    toml = configuration.build_toml(
        address="127.0.0.1",
        port=20449,
        domain="cover.example",
        users={"u+ab/cd=": "b" * 32},
    )

    assert '"u+ab/cd=" = "' + "b" * 32 + '"' in toml

    tomllib = pytest.importorskip("tomllib", reason="stdlib TOML parser needs Python 3.11+")
    assert tomllib.loads(toml)["access"]["users"]["u+ab/cd="] == "b" * 32


def test_lifecycle_uses_hydra_paths_and_least_privilege_unit(tmp_path):
    class Host:
        def __init__(self):
            self.commands = []

        def run(self, args, **_kwargs):
            self.commands.append(args)
            return CompletedProcess(args, 0, "active", "")

        def atomic_write(self, path, content, **_kwargs):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        def ensure_directory(self, path, **_kwargs):
            path.mkdir(parents=True, exist_ok=True)

    host = Host()
    service = tmp_path / "mtproto-zig.service"
    config = tmp_path / "config.toml"
    binary = tmp_path / "mtproto-zig"
    binary.write_bytes(b"\\x7fELF")
    assert installation.write_service(
        host=host, service_file=service, binary=binary, config=config, work_dir=tmp_path / "work", service="mtproto-zig"
    )
    unit = service.read_text(encoding="utf-8")
    assert "User=mtproto-zig" in unit
    assert "CAP_NET_ADMIN" not in unit
    assert runtime.apply(
        "[server]\\nport = 443\\n",
        host=host,
        config_file=config,
        work_dir=tmp_path / "work",
        service="mtproto-zig",
        binary=binary,
    )
    assert ["chown", "root:mtproto-zig", str(config)] in host.commands
    # A root-owned work directory makes systemd fail with status=200/CHDIR.
    assert ["chown", "mtproto-zig:mtproto-zig", str(tmp_path / "work")] in host.commands
    # daemon-reload accepts no unit name; passing one fails with "Too many arguments."
    reloads = [command for command in host.commands if command[1] == "daemon-reload"]
    assert reloads
    assert all(len(command) == 2 for command in reloads)


def test_metrics_accumulate_across_counter_reset(tmp_path):
    app_state = state()
    username = derive_username("user-a")
    samples = iter(
        (
            f'mtproto_user_client_to_upstream_bytes_total{{user="{username}"}} 10\nmtproto_user_upstream_to_client_bytes_total{{user="{username}"}} 5\n',
            f'mtproto_user_client_to_upstream_bytes_total{{user="{username}"}} 3\nmtproto_user_upstream_to_client_bytes_total{{user="{username}"}} 2\n',
        )
    )
    first, _ = observation.traffic(app_state, totals_file=tmp_path / "totals.json", metrics=lambda: next(samples))
    second, _ = observation.traffic(app_state, totals_file=tmp_path / "totals.json", metrics=lambda: next(samples))
    assert first["a@example"] == 15
    assert second["a@example"] == 20
