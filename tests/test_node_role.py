"""A node install must never expose the base server's management surface."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

import main as entry
from hydra.core import node_identity
from hydra.contracts.node_validation import NODE_CONTRACT_VERSION
from hydra.core.node_identity import (
    NodeIdentity,
    identity_from_document,
    is_node_install,
    load_node_identity,
)
from hydra.core.state import AppState


def _identity_document(**overrides) -> dict:
    document = {
        "contract_version": NODE_CONTRACT_VERSION,
        "node_id": "de-1",
        "base_url": "https://base.example.com:8443",
        "base_ip": "192.0.2.1",
        "control_port": 9444,
        "certificate": "/etc/hydra/node/node.crt",
        "private_key": "/etc/hydra/node/node.key",
        "base_ca": "/etc/hydra/node/base-ca.crt",
        "base_fingerprint": "a" * 64,
    }
    document.update(overrides)
    return document


def _install_identity(monkeypatch, tmp_path, document: dict) -> None:
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(node_identity, "NODE_IDENTITY_FILE", path)


def test_absent_identity_means_a_base_server(tmp_path, monkeypatch):
    monkeypatch.setattr(node_identity, "NODE_IDENTITY_FILE", tmp_path / "missing.json")
    assert load_node_identity() is None
    assert is_node_install() is False


def test_valid_identity_loads(tmp_path, monkeypatch):
    _install_identity(monkeypatch, tmp_path, _identity_document())
    identity = load_node_identity()
    assert identity == NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:8443",
        base_ip="192.0.2.1",
        control_port=9444,
        certificate="/etc/hydra/node/node.crt",
        private_key="/etc/hydra/node/node.key",
        base_ca="/etc/hydra/node/base-ca.crt",
        base_fingerprint="a" * 64,
    )
    assert is_node_install() is True


def test_a_malformed_identity_still_counts_as_a_node_install(tmp_path, monkeypatch):
    """Falling back to full management on a node would be the dangerous failure."""
    _install_identity(monkeypatch, tmp_path, {"node_id": "de-1"})
    assert is_node_install() is True
    with pytest.raises(ValueError, match="missing"):
        load_node_identity()


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"base_url": "http://base.example.com:8443"}, "https origin"),
        ({"base_url": "base.example.com"}, "https origin"),
        ({"private_key": "relative.key"}, "absolute path"),
        ({"certificate": "/etc/hydra/../../etc/shadow"}, "must not contain"),
        ({"contract_version": NODE_CONTRACT_VERSION + 1}, "not supported"),
        ({"base_fingerprint": "invalid"}, "base_fingerprint"),
        ({"base_ip": "base.example.com"}, "base_ip"),
        ({"control_port": 0}, "control_port"),
        ({"node_id": "de 1"}, "node_id"),
        ({"unexpected": "field"}, "unsupported fields"),
    ],
)
def test_identity_rejects_unsafe_values(overrides, message):
    with pytest.raises(ValueError, match=message):
        identity_from_document(_identity_document(**overrides))


def _run_entrypoint(monkeypatch, *, node_install: bool) -> tuple[MagicMock, MagicMock]:
    main_menu = MagicMock()
    emergency = MagicMock()
    monkeypatch.setattr(node_identity, "is_node_install", lambda: node_install)
    monkeypatch.setattr(sys, "argv", ["hydra"])
    with (
        patch("main.check_root"),
        patch("hydra.core.state.load_state", return_value=AppState()),
        patch("hydra.bootstrap.production_application", return_value=MagicMock()),
        patch("hydra.ui.menus.main_menu", main_menu),
        patch("hydra.ui._menus.node_emergency.run_node_emergency_menu", emergency),
    ):
        entry.main()
    return main_menu, emergency


def test_node_install_reaches_only_the_emergency_menu(monkeypatch):
    main_menu, emergency = _run_entrypoint(monkeypatch, node_install=True)
    main_menu.assert_not_called()
    emergency.assert_called_once()


def test_base_install_reaches_the_main_menu(monkeypatch):
    main_menu, emergency = _run_entrypoint(monkeypatch, node_install=False)
    main_menu.assert_called_once()
    emergency.assert_not_called()


def test_node_install_rejects_shared_management_cli(monkeypatch):
    monkeypatch.setattr(node_identity, "is_node_install", lambda: True)
    monkeypatch.setattr(sys, "argv", ["hydra", "user", "list"])
    with (
        patch("hydra.cli.main") as cli_main,
        pytest.raises(SystemExit) as exit_info,
    ):
        entry.main()
    assert exit_info.value.code == 2
    cli_main.assert_not_called()


def test_emergency_menu_is_read_only():
    """No mutating application call may appear in the node's local surface."""
    from hydra.ui._menus import node_emergency

    source = node_emergency.__file__
    assert source is not None
    text = open(source, encoding="utf-8").read()
    for forbidden in (
        "apply_config",
        "save_state",
        "update_state",
        "admin.start_unit",
        "admin.stop_unit",
        "admin.restart_unit",
        "protocols.enable",
        "protocols.disable",
        "protocols.install",
        "users.add",
        "users.remove",
        "uninstall",
    ):
        assert forbidden not in text, f"emergency surface mutates via {forbidden}"


def test_emergency_menu_shows_status_and_exits(monkeypatch, tmp_path):
    from hydra.ui._menus import node_emergency

    app = MagicMock()
    app.admin.load_state.return_value = AppState()
    app.protocols.list.return_value = []
    app.last_apply_error.return_value = "sing-box не запустился"
    app.apply_journal.return_value = tmp_path / "apply.jsonl"
    monkeypatch.setattr(node_identity, "NODE_IDENTITY_FILE", tmp_path / "missing.json")
    with (
        patch.object(node_emergency, "menu", side_effect=["1", "0"]),
        patch.object(node_emergency, "clear"),
        patch.object(node_emergency, "title"),
        patch.object(node_emergency, "panel") as show_panel,
        patch.object(node_emergency, "prompt"),
        patch.object(node_emergency, "error") as show_error,
    ):
        node_emergency.run_node_emergency_menu(AppState(), app)

    app.admin.load_state.assert_called()
    show_panel.assert_called()
    show_error.assert_called_once()
    for mutating in ("apply_config", "add_user", "save_state"):
        assert not getattr(app, mutating).called
