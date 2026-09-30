from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from hydra.core.node_identity import NodeIdentity
from hydra.core.host import HostBackend
from hydra.services.nodes.firewall import (
    apply_control_firewall,
    remove_control_firewall,
    render_control_firewall,
)


def _identity(*, base_ip="192.0.2.10", control_port=9444):
    return NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip=base_ip,
        control_port=control_port,
        certificate="/etc/hydra/node/node.crt",
        private_key="/etc/hydra/node/node.key",
        base_ca="/etc/hydra/node/base-ca.crt",
        base_fingerprint="a" * 64,
    )


@pytest.mark.parametrize(
    ("address", "family"),
    [("192.0.2.10", "ip"), ("2001:db8::10", "ip6")],
)
def test_control_firewall_allows_only_the_pinned_base_and_port(address, family):
    ruleset = render_control_firewall(_identity(base_ip=address, control_port=9445))

    assert f"{family} saddr {address} tcp dport 9445 accept" in ruleset
    assert "tcp dport 9445 drop" in ruleset
    assert "policy accept" in ruleset


def test_control_firewall_restores_existing_table_when_apply_fails():
    host = HostBackend()
    previous = "table inet hydra-node-control { }\n"
    results = [
        CompletedProcess([], 0, stdout="table inet hydra-node-control\n", stderr=""),
        CompletedProcess([], 0, stdout=previous, stderr=""),
        CompletedProcess([], 0, stdout="", stderr=""),
        CompletedProcess([], 1, stdout="", stderr="invalid"),
        CompletedProcess([], 0, stdout="", stderr=""),
    ]
    with (
        patch.object(host, "which", return_value="/usr/sbin/nft"),
        patch.object(host, "run", side_effect=results) as run,
    ):
        with pytest.raises(RuntimeError, match="could not apply node control firewall"):
            apply_control_firewall(_identity(), host=host)

    commands = [call.args[0] for call in run.call_args_list]
    assert commands[0] == ["nft", "list", "tables"]
    assert commands[1] == ["nft", "list", "table", "inet", "hydra-node-control"]
    assert commands[2] == ["nft", "--check", "-f", "-"]
    assert commands[3] == ["nft", "-f", "-"]
    assert commands[4] == ["nft", "-f", "-"]
    expected_batch = "delete table inet hydra-node-control\n" + render_control_firewall(_identity())
    assert run.call_args_list[2].kwargs["input"] == expected_batch
    assert run.call_args_list[3].kwargs["input"] == expected_batch
    assert run.call_args_list[4].kwargs["input"] == "delete table inet hydra-node-control\n" + previous


def test_remove_control_firewall_deletes_only_the_hydra_owned_table():
    host = HostBackend()
    results = [
        CompletedProcess([], 0, stdout="table inet hydra-node-control\ntable inet filter\n", stderr=""),
        CompletedProcess([], 0, stdout="", stderr=""),
    ]
    with (
        patch.object(host, "which", return_value="/usr/sbin/nft"),
        patch.object(host, "run", side_effect=results) as run,
    ):
        remove_control_firewall(host=host)

    assert [call.args[0] for call in run.call_args_list] == [
        ["nft", "list", "tables"],
        ["nft", "-f", "-"],
    ]
    assert run.call_args_list[1].kwargs["input"] == "delete table inet hydra-node-control\n"


def test_remove_control_firewall_is_idempotent_when_table_is_absent():
    host = HostBackend()
    with (
        patch.object(host, "which", return_value="/usr/sbin/nft"),
        patch.object(
            host,
            "run",
            return_value=CompletedProcess([], 0, stdout="table inet filter\n", stderr=""),
        ) as run,
    ):
        remove_control_firewall(host=host)

    run.assert_called_once_with(["nft", "list", "tables"], timeout=15, text=True, input=None)
