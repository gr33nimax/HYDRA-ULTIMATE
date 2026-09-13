"""Exercise the actual Naive installer with a fake compiler and host."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hydra.core import sni_router_install
from hydra.core.state_models import AppState
from hydra.plugins.naive.plugin import NaivePlugin


@pytest.mark.parametrize("valid", [True, False])
def test_naive_candidate_is_validated_before_binary_replacement(tmp_path, monkeypatch, valid):
    plugin = NaivePlugin()
    binary = tmp_path / "caddy-naive"
    binary.write_bytes(b"old")
    layout = replace(plugin._runtime_layout(), binary=binary)
    monkeypatch.setattr(plugin, "_runtime_layout", lambda: layout)
    monkeypatch.setattr(sni_router_install, "ensure_modern_go", lambda *a, **k: True)
    monkeypatch.setattr(sni_router_install.os, "makedirs", Mock())
    monkeypatch.setattr(sni_router_install, "_ensure_xcaddy_binary", lambda *a: "xcaddy")
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0] == "xcaddy":
            assert sni_router_install.NAIVE_FORWARD_PROXY_MODULE in args
            assert args[2] == "v2.10.2"
            assert not any("caddy-l4" in argument for argument in args)
            Path(args[-1]).write_bytes(b"candidate")
        if "validate" in args:
            assert binary.read_bytes() == b"old"
            assert Path(args[0]).read_bytes() == b"candidate"
            assert "passthrough_uot" in Path(args[3]).read_text()
            return SimpleNamespace(returncode=0 if valid else 1, stdout="", stderr="invalid")
        return SimpleNamespace(returncode=0, stdout="http.handlers.forward_proxy", stderr="")

    monkeypatch.setattr(plugin, "_host_backend", lambda: SimpleNamespace(run=run))
    assert plugin._download_binary() is valid
    assert any("validate" in args for args in calls)
    assert binary.read_bytes() == (b"candidate" if valid else b"old")
    if valid:
        assert binary.with_suffix(".previous").read_bytes() == b"old"


def test_naive_install_repairs_missing_unit_without_rebuilding(tmp_path, monkeypatch):
    plugin = NaivePlugin()
    layout = replace(
        plugin._runtime_layout(),
        binary=tmp_path / "caddy-naive",
        service_file=tmp_path / "caddy-naive.service",
    )
    layout.binary.write_bytes(b"managed binary")
    monkeypatch.setattr(plugin, "_runtime_layout", lambda: layout)
    install_service = Mock(side_effect=lambda: layout.service_file.write_text(
        "[Service]", encoding="utf-8",
    ))
    download_binary = Mock()
    monkeypatch.setattr(plugin, "_install_service", install_service)
    monkeypatch.setattr(plugin, "_download_binary", download_binary)

    assert plugin.install()
    install_service.assert_called_once_with()
    download_binary.assert_not_called()


def test_naive_upgrade_restarts_and_rollback_restores_binary_and_config(tmp_path, monkeypatch):
    plugin = NaivePlugin()
    layout = replace(
        plugin._runtime_layout(), binary=tmp_path / "caddy-naive",
        config_dir=tmp_path, caddyfile=tmp_path / "Caddyfile",
        service_file=tmp_path / "caddy.service", log_dir=tmp_path / "logs",
        data_dir=tmp_path / "data",
    )
    layout.binary.write_bytes(b"old-binary")
    layout.caddyfile.write_bytes(b"old-config")
    layout.service_file.write_bytes(b"old-service")
    monkeypatch.setattr(plugin, "_runtime_layout", lambda: layout)
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout="active", stderr=""))
    monkeypatch.setattr(plugin, "_host_backend", lambda: SimpleNamespace(run=run))
    snapshot = plugin.snapshot(AppState())
    plugin._pending_cfg = "new-config"
    monkeypatch.setattr(plugin, "_create_fake_site", Mock())
    monkeypatch.setattr(plugin, "_validate_caddy", Mock(side_effect=["passthrough_uot", None]))

    def upgrade(config):
        assert config.read_text() == "new-config"
        layout.binary.with_suffix(".previous").write_bytes(layout.binary.read_bytes())
        layout.binary.write_bytes(b"new-binary")
        plugin._binary_replaced = True
        return True

    monkeypatch.setattr(plugin, "_download_binary", upgrade)
    run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="restart failed")
    assert not plugin.apply(AppState())
    assert ["systemctl", "restart", layout.service_name] in [call.args[0] for call in run.call_args_list]
    run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
    assert plugin.rollback(AppState(), snapshot)
    assert layout.binary.read_bytes() == b"old-binary"
    assert layout.caddyfile.read_bytes() == b"old-config"
    assert layout.service_file.read_bytes() == b"old-service"
