from unittest.mock import MagicMock, patch

import hydra.entrypoints.node_control as node_control

from hydra.core.host import HOST
from hydra.core.node_identity import NodeIdentity


def test_node_agent_does_not_start_without_identity():
    with (
        patch.object(node_control, "load_node_identity", return_value=None),
        patch.object(node_control, "create_control_server") as create_server,
    ):
        assert node_control.main() == 2
    create_server.assert_not_called()


def test_node_agent_wires_composition_root_operations_and_closes_server():
    identity = NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="192.0.2.1",
        certificate="/etc/hydra/node/node.crt",
        private_key="/etc/hydra/node/node.key",
        base_ca="/etc/hydra/node/base-ca.crt",
        base_fingerprint="a" * 64,
    )
    operations = MagicMock()
    server = MagicMock()
    server.serve_forever.side_effect = KeyboardInterrupt
    with (
        patch.object(node_control, "load_node_identity", return_value=identity),
        patch.object(node_control, "apply_control_firewall") as apply_firewall,
        patch.object(node_control, "production_node_reconciler", return_value=operations) as build_operations,
        patch.object(node_control, "create_control_server", return_value=server) as create_server,
    ):
        assert node_control.main() == 0
    apply_firewall.assert_called_once_with(identity, host=HOST)
    build_operations.assert_called_once_with(identity.node_id)
    create_server.assert_called_once_with(identity, operations, port=identity.control_port)
    server.serve_forever.assert_called_once()
    server.server_close.assert_called_once()


def test_node_agent_does_not_listen_when_firewall_cannot_be_applied():
    identity = NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="192.0.2.1",
        certificate="/etc/hydra/node/node.crt",
        private_key="/etc/hydra/node/node.key",
        base_ca="/etc/hydra/node/base-ca.crt",
        base_fingerprint="a" * 64,
    )
    with (
        patch.object(node_control, "load_node_identity", return_value=identity),
        patch.object(node_control, "apply_control_firewall", side_effect=RuntimeError("nft unavailable")),
        patch.object(node_control, "create_control_server") as create_server,
    ):
        assert node_control.main() == 2
    create_server.assert_not_called()
