from hydra.core.state import AppState, PluginState, User
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

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
    assert first is not None
    assert second is not None
    assert first["a@example"] == 15
    assert second["a@example"] == 20


def _two_user_state():
    result = AppState(
        users=[User(email="a@example", uuid="user-a"), User(email="b@example", uuid="user-b")],
        protocols={"mtproto_zig": PluginState(enabled=True)},
    )
    return result


def _upstream_sample(user_a: str, user_b: str) -> str:
    """A real upstream-shaped exposition: HELP/TYPE headers plus both counters."""
    return (
        "# HELP mtproto_user_client_to_upstream_bytes_total Bytes successfully written upstream by configured user\n"
        "# TYPE mtproto_user_client_to_upstream_bytes_total counter\n"
        f'mtproto_user_client_to_upstream_bytes_total{{user="{user_a}"}} 120\n'
        f'mtproto_user_upstream_to_client_bytes_total{{user="{user_a}"}} 880\n'
        "# HELP mtproto_user_upstream_to_client_bytes_total Bytes successfully written to client by configured user\n"
        "# TYPE mtproto_user_upstream_to_client_bytes_total counter\n"
        f'mtproto_user_client_to_upstream_bytes_total{{user="{user_b}"}} 7\n'
        f'mtproto_user_upstream_to_client_bytes_total{{user="{user_b}"}} 3\n'
    )


def test_upstream_metrics_sample_maps_each_user_to_its_counter(tmp_path):
    app_state = _two_user_state()
    payload = _upstream_sample(derive_username("user-a"), derive_username("user-b"))

    totals, reason = observation.traffic(
        app_state, totals_file=tmp_path / "totals.json", metrics=lambda: payload
    )

    assert reason == ""
    assert totals == {"a@example": 1000, "b@example": 10}


def test_http_200_without_user_series_is_unavailable(tmp_path):
    app_state = _two_user_state()
    totals_file = tmp_path / "totals.json"
    payload = _upstream_sample(derive_username("user-a"), derive_username("user-b"))
    good, _ = observation.traffic(app_state, totals_file=totals_file, metrics=lambda: payload)
    headers_only = (
        "# HELP mtproto_user_client_to_upstream_bytes_total Bytes successfully written upstream by configured user\n"
        "# TYPE mtproto_user_client_to_upstream_bytes_total counter\n"
    )

    totals, reason = observation.traffic(app_state, totals_file=totals_file, metrics=lambda: headers_only)

    assert good == {"a@example": 1000, "b@example": 10}
    assert totals is None
    assert "серий" in reason
    # The last good totals survive the failure and the next scrape.
    again, _ = observation.traffic(app_state, totals_file=totals_file, metrics=lambda: payload)
    assert again == good


def test_metrics_label_mismatch_is_unavailable(tmp_path):
    app_state = _two_user_state()
    payload = _upstream_sample(derive_username("ghost-a"), derive_username("ghost-b"))

    totals, reason = observation.traffic(
        app_state, totals_file=tmp_path / "totals.json", metrics=lambda: payload
    )

    assert totals is None
    assert "метки" in reason


def test_plugin_scrape_failure_is_observable_in_status_and_health():
    plugin = MtprotoZigPlugin()
    app_state = _two_user_state()
    failure = (None, "metrics недоступны (ConnectionRefusedError)")

    with (
        patch.object(MtprotoZigPlugin, "_installed", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.HOST.run") as run,
        patch("hydra.plugins.mtproto_zig.observation.traffic", return_value=failure),
    ):
        run.return_value = CompletedProcess(["systemctl"], 0, "active\n", "")
        assert plugin.traffic_snapshot(app_state) is None
        assert plugin.traffic(app_state) == {}
        assert plugin.traffic_source_reason(app_state) == failure[1]
        status = plugin.status(app_state)
        health = plugin.healthcheck_for_state(app_state)

    assert status.info["traffic_source"] == failure[1]
    assert health.healthy is True
    assert "источник трафика недоступен" in health.detail
