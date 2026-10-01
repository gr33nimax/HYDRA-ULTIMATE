"""Exercise the node wizard with its real application service, not a permissive Mock."""

from contextlib import nullcontext
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.plugins.defaults import default_plugins
from hydra.services.application import ApplicationService
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.onboarding import NodeProvisioningPort
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.ui._menus import nodes_setup


SHA = "a" * 40


@pytest.mark.parametrize("supported", [True, False])
def test_wizard_checks_node_support_through_real_manager_before_ssh(tmp_path, supported, capsys):
    state = AppState()
    branches = []
    requests = []

    def resolve_branch(branch):
        branches.append(branch)
        return SHA

    def no_side_effect(*args, **kwargs):
        raise AssertionError("confirmation was declined; state and VPS must not change")

    def urlopen(request, *, timeout):
        requests.append((request.full_url, request.get_method(), timeout))
        return nullcontext(SimpleNamespace(status=200 if supported else 404))

    manager = NodeManager(
        state_reader=lambda: state,
        state_updater=no_side_effect,
        client_for=no_side_effect,
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
        bootstrap=cast(
            NodeProvisioningPort,
            SimpleNamespace(
                resolve_revision=resolve_branch,
                install=no_side_effect,
                provision_control_identity=no_side_effect,
            ),
        ),
    )
    app = SimpleNamespace(
        nodes=manager,
        admin=SimpleNamespace(
            unit_active=lambda name: name == "hydra-sub",
            subscription_certificate=lambda state: ("cert", "key"),
            subscription_public_host=lambda state: "base.example.com",
        ),
        protocols=SimpleNamespace(
            list=lambda category: [plugin for plugin in default_plugins() if plugin.meta.category == category],
        ),
    )
    inputs = [
        "node.example.com",
        "root",
        "uk-1",
        "UK",
        "2",  # Identity, then dev.
        "2",
        "1",
        "2",
        "UK AWG 3.1",  # AmneziaWG 3.1.
        "3",
        "1",
        "any.node.example.com",
        "2",
        "UK AnyTLS",
        "7",
        "1",
        "2",
        "mask.example.com",
        "1",
        "/xhttp",
        "8",
        "UK VLESS",
        "13",
        "0",  # Done, then decline installation.
    ]
    with (
        patch("builtins.input", side_effect=inputs),
        patch("getpass.getpass", return_value=""),
        patch("hydra.services.nodes.revision.urllib.request.urlopen", side_effect=urlopen),
    ):
        nodes_setup.install_node(state, cast(ApplicationService, app))
    output = capsys.readouterr().out
    assert branches == ["dev"]
    assert requests == [
        (
            f"https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/{SHA}/deploy/hydra-node-control.service",
            "HEAD",
            10,
        )
    ]
    assert "object has no attribute" not in output
    if supported:
        assert "ПЛАН УСТАНОВКИ" in output and SHA in output
        assert "Установка отменена; VPS не изменялась" in output
    else:
        assert "не содержит режим ноды" in output
        assert "ПЛАН УСТАНОВКИ" not in output
    assert state == AppState()
    assert not (tmp_path / "exports").exists()


def test_error_before_provisioning_is_not_reported_as_an_ssh_failure():
    detail = nodes_setup.InstallLog().failure(AttributeError("missing capability check"))
    assert detail == "Подготовка установки: missing capability check"
    assert "SSH" not in detail
