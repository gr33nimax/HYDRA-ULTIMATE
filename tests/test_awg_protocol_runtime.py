from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.amneziawg.configuration import client_marker_name
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.services.plugin_commands import PluginCommandService


def _result(code=0, stdout="", stderr=""):
    return MagicMock(returncode=code, stdout=stdout, stderr=stderr)


def test_protocol_mode_uses_only_upstream_noninteractive_commands(tmp_path):
    script = tmp_path / "amneziawg-install.sh"
    script.write_text("#!/bin/bash", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    plugin = AmneziaWGPlugin()

    with (
        patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path),
        patch(
            "hydra.plugins.amneziawg.installation.HOST.run",
            side_effect=[
                _result(stdout="https://github.com/wiresock/amneziawg-install.git\n"),
                _result(stdout="abc\n"),
                _result(stdout="3.1\n"),
                _result(),
                _result(stdout="https://github.com/wiresock/amneziawg-install.git\n"),
                _result(stdout="abc\n"),
                _result(),
            ],
        ) as run,
    ):
        assert plugin.observed_protocol_mode() == "3.1"
        plugin.migrate_protocol_mode("3.0")

    assert run.call_args_list[2].args[0] == ["bash", str(script), "--protocol-status"]
    assert run.call_args_list[3].args[0] == ["dpkg", "--audit"]
    assert run.call_args_list[6].args[0] == ["bash", str(script), "--enable-awg3"]


def test_protocol_migration_reports_the_installer_reason(tmp_path):
    # A migration that refuses without saying why leaves the operator with a server in one mode
    # and a button that does nothing: the installer's own line is the whole diagnosis.
    script = tmp_path / "amneziawg-install.sh"
    script.write_text("#!/bin/bash", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    plugin = AmneziaWGPlugin()

    with (
        patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path),
        patch(
            "hydra.plugins.amneziawg.installation.HOST.run",
            side_effect=[
                _result(),
                _result(stdout="https://github.com/wiresock/amneziawg-install.git\n"),
                _result(stdout="abc\n"),
                _result(code=1, stdout="ERROR: awg3 kernel module is not available\n", stderr=""),
            ],
        ),
    ):
        with pytest.raises(RuntimeError, match="awg3 kernel module is not available"):
            plugin.migrate_protocol_mode("3.0")


def _migration_host(script, observe, code=0, stdout=""):
    """Host stub answering exactly what the migration path asks for."""

    def run(command, **kwargs):
        if command == ["dpkg", "--audit"]:
            return _result()
        if command[:2] == ["git", "-C"]:
            if "config" in command:
                return _result(stdout="https://github.com/wiresock/amneziawg-install.git\n")
            return _result(stdout="abc\n")
        if command[:2] == ["bash", str(script)]:
            observe()
            return _result(code=code, stdout=stdout)
        return _result()

    return run


def _migrating_plugin(tmp_path):
    script = tmp_path / "amneziawg-install.sh"
    script.write_text("#!/bin/bash", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    return script, AmneziaWGPlugin()


def test_protocol_migration_lends_the_installer_client_configs(tmp_path):
    # The installer proves every peer against a client configuration and refuses the whole
    # operation without one — which is what stopped a live server whose peers HYDRA created.
    script, plugin = _migrating_plugin(tmp_path)
    marker = client_marker_name("alice@example.com")
    client_conf = tmp_path / f"awg0-client-{marker}.conf"
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"amneziawg": PluginState(installed=True, config={})},
    )
    lent: list[str] = []

    def observe():
        lent.append(client_conf.read_text(encoding="utf-8") if client_conf.exists() else "")

    with (
        patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path),
        patch.object(AmneziaWGPlugin, "CLIENT_CONFIG_DIR", tmp_path),
        patch.object(plugin, "generate_client_config", return_value="[Interface]\nPrivateKey = alice-key\n"),
        patch("hydra.plugins.amneziawg.installation.HOST.run", side_effect=_migration_host(script, observe)),
    ):
        plugin.migrate_protocol_mode("3.0", state)

    assert lent and "PrivateKey = alice-key" in lent[0], "the installer was not given the client config"
    assert not client_conf.exists(), "a private key was left behind after the migration"


def test_protocol_migration_cleans_up_after_a_refusal_and_restores_a_foreign_file(tmp_path):
    script, plugin = _migrating_plugin(tmp_path)
    marker = client_marker_name("alice@example.com")
    client_conf = tmp_path / f"awg0-client-{marker}.conf"
    client_conf.write_text("[Interface]\nPrivateKey = someone-elses-key\n", encoding="utf-8")
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"amneziawg": PluginState(installed=True, config={})},
    )
    borrowed: list[str] = []

    def observe():
        borrowed.append(client_conf.read_text(encoding="utf-8"))

    with (
        patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path),
        patch.object(AmneziaWGPlugin, "CLIENT_CONFIG_DIR", tmp_path),
        patch.object(plugin, "generate_client_config", return_value="[Interface]\nPrivateKey = alice-key\n"),
        patch(
            "hydra.plugins.amneziawg.installation.HOST.run",
            side_effect=_migration_host(script, observe, code=1, stdout="ERROR: no recoverable config\n"),
        ),
    ):
        with pytest.raises(RuntimeError, match="no recoverable config"):
            plugin.migrate_protocol_mode("3.0", state)

    assert borrowed and "alice-key" in borrowed[0], "the installer saw someone else's file"
    assert client_conf.read_text(encoding="utf-8").count("someone-elses-key") == 1
    assert not list(tmp_path.glob("*.hydra-backup")), "a borrowed file was left aside"


def test_protocol_mode_rejects_missing_or_invalid_upstream_status(tmp_path):
    plugin = AmneziaWGPlugin()
    with patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path):
        with pytest.raises(RuntimeError, match="installer"):
            plugin.observed_protocol_mode()

    script = tmp_path / "amneziawg-install.sh"
    script.write_text("#!/bin/bash", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    with (
        patch("hydra.plugins.amneziawg.installation.AWG_INSTALL_DIR", tmp_path),
        patch(
            "hydra.plugins.amneziawg.installation.HOST.run",
            side_effect=[
                _result(stdout="https://github.com/wiresock/amneziawg-install.git\n"),
                _result(stdout="abc\n"),
                _result(stdout="bad"),
            ],
        ),
    ):
        with pytest.raises(RuntimeError, match="invalid protocol status"):
            plugin.observed_protocol_mode()


def test_protocol_mode_status_opens_awg31_exports_on_a_supporting_core():
    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={"protocol_mode": "3.1"})})

    with (
        patch.object(plugin, "observed_protocol_mode", return_value="3.1"),
        patch("hydra.plugins.amneziawg.client_links.kernel_supports_awg31", return_value=True),
    ):
        status = plugin.protocol_mode_status(state)

    assert status["desired"] == "3.1"
    assert status["observed"] == "3.1"
    exports = status["exports"]
    assert isinstance(exports, dict)
    assert exports["native_conf"] == "ready"
    assert exports["wg_uri"] == "ready"
    assert exports["vpn_uri"] == "ready"
    assert exports["singbox"] == "ready"
    assert exports["hydrabox_subscription"] == "ready"
    assert exports["sn_awg"] == "unsupported: AWG 3.1 importer compatibility is unverified"


def test_protocol_mode_status_keeps_awg31_exports_closed_on_an_old_core():
    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={"protocol_mode": "3.1"})})

    with (
        patch.object(plugin, "observed_protocol_mode", return_value="3.1"),
        patch("hydra.plugins.amneziawg.client_links.kernel_supports_awg31", return_value=False),
    ):
        exports = plugin.protocol_mode_status(state)["exports"]

    assert isinstance(exports, dict)
    assert exports["native_conf"] == "ready"
    for key in ("singbox", "hydrabox_subscription"):
        assert exports[key].startswith("unsupported: AWG 3.1 requires a HydraCore")


def test_protocol_mode_status_allows_only_source_proven_awg30_sbe_exports():
    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={"protocol_mode": "3.0"})})

    with patch.object(plugin, "observed_protocol_mode", return_value="3.0"):
        exports = plugin.protocol_mode_status(state)["exports"]

    assert isinstance(exports, dict)
    assert exports["singbox"] == "ready"
    assert exports["hydrabox_subscription"] == "ready"
    assert exports["sn_awg"] == "unsupported: AWG 3.0 importer compatibility is unverified"


def test_awg31_core_gate_compares_real_version_strings():
    from hydra.plugins.amneziawg.client_links import kernel_supports_awg31

    def with_version(version):
        with patch("hydra.core.singbox.get_version", return_value=version):
            return kernel_supports_awg31()

    assert with_version("v1.14.0-extended-2.7.1-hydracore.12") is True
    assert with_version("v1.14.0-extended-2.7.1-hydracore.12-debug.2") is True
    assert with_version("v1.13.16-extended-hydracore.11-debug.61") is False
    assert with_version("v1.14.0-extended-2.7.1-hydracore.1") is False
    assert with_version("") is False
    with patch("hydra.core.singbox.get_version", side_effect=RuntimeError("no core")):
        assert kernel_supports_awg31() is False


def test_set_protocol_mode_migrates_then_persists_only_verified_mode(tmp_path):
    conf = tmp_path / "awg0.conf"
    conf.write_text(
        "[Interface]\nHeaderProtectionKey = header\nContentPaddingAddition = 1\n"
        "RekeyAfterTime = 1\nRekeyTimeout = 1\nRejectAfterTime = 1\nKeepaliveTimeout = 1\n",
        encoding="utf-8",
    )
    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={})})

    with (
        patch.object(plugin, "_conf_path", return_value=conf),
        patch.object(plugin, "observed_protocol_mode", side_effect=["2.0", "3.0"]),
        patch.object(plugin, "migrate_protocol_mode") as migrate,
    ):
        assert plugin.set_protocol_mode(state, "3.0") is True

    migrate.assert_called_once_with("3.0", state)
    assert state.protocols["amneziawg"].config["protocol_mode"] == "3.0"


def test_protocol_mode_rolls_back_upstream_when_apply_fails(tmp_path):
    conf = tmp_path / "awg0.conf"
    conf.write_text(
        "[Interface]\nHeaderProtectionKey = header\nContentPaddingAddition = 1\n"
        "RekeyAfterTime = 1\nRekeyTimeout = 1\nRejectAfterTime = 1\nKeepaliveTimeout = 1\n",
        encoding="utf-8",
    )
    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, enabled=True, config={})})
    service = PluginCommandService(
        get_plugin=lambda name: plugin if name == "amneziawg" else None,
        apply_config=lambda current: False,
        save_state=lambda current: None,
    )

    with (
        patch.object(plugin, "_conf_path", return_value=conf),
        patch.object(plugin, "_is_up", return_value=False),
        patch.object(plugin, "_is_up_iface", return_value=False),
        patch.object(plugin, "installer_identity", return_value="abc"),
        patch.object(plugin, "observed_protocol_mode", side_effect=["2.0", "2.0", "3.0", "3.0"]),
        patch.object(plugin, "migrate_protocol_mode") as migrate,
        patch("hydra.plugins.amneziawg.runtime.HOST.run", return_value=_result()),
    ):
        # noqa: S608 - PluginCommandService allowlists this literal plugin command.
        assert service.execute(state, "amneziawg", "set_protocol_mode", mode="3.0") is False

    assert migrate.call_args_list == [(("3.0", state), {}), (("2.0", state), {})]
    assert "protocol_mode" not in state.protocols["amneziawg"].config


def test_snapshot_includes_params_and_rollback_restores_them(tmp_path):
    desktop = tmp_path / "awg0.conf"
    mobile = tmp_path / "awg1.conf"
    params = tmp_path / "params"
    desktop.write_text("desktop-old", encoding="utf-8")
    mobile.write_text("mobile-old", encoding="utf-8")
    params.write_text("params-old", encoding="utf-8")
    plugin = AmneziaWGPlugin()

    with (
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop),
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile),
        patch("hydra.plugins.amneziawg.runtime.AWG_PARAMS", params),
        patch.object(plugin, "_is_up", return_value=True),
        patch.object(plugin, "_is_up_iface", return_value=False),
        patch("hydra.plugins.amneziawg.runtime.HOST.run", return_value=_result()),
    ):
        state = AppState()
        snapshot = plugin.snapshot(state)
        params.write_text("changed", encoding="utf-8")
        assert plugin.rollback(state, snapshot) is True

    assert params.read_text(encoding="utf-8") == "params-old"
    # Windows ACLs do not expose POSIX chmod bits; Linux smoke checks 0600.
