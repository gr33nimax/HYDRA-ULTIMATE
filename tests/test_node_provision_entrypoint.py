import io
import json
import os
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import hydra.entrypoints.node_provision as node_provision
from hydra.core.node_identity import NodeIdentity


_BASE_CERTIFICATE = "-----BEGIN CERTIFICATE-----\npublic-base-cert\n-----END CERTIFICATE-----\n"


@pytest.fixture(autouse=True)
def root_posix_environment(monkeypatch):
    monkeypatch.setattr(node_provision, "os", SimpleNamespace(
        name="posix", geteuid=lambda: 0, environ=os.environ,
    ))


def test_provision_rejects_non_root_before_reading_request_or_mutation(monkeypatch):
    monkeypatch.setattr(node_provision.os, "geteuid", lambda: 1000)
    with (
        patch.object(node_provision.sys, "stdin", Mock()) as source,
        patch.object(node_provision, "provision_node_identity") as provision,
        patch.object(node_provision, "production_node_uninstall") as uninstall,
        patch.object(node_provision.HOST, "systemd") as systemd,
    ):
        assert node_provision.main() == 2
    source.read.assert_not_called()
    provision.assert_not_called()
    uninstall.assert_not_called()
    systemd.assert_not_called()


def _payload():
    return {
        "node_id": "de-1",
        "base_url": "https://base.example.com:9444",
        "control_address": "node.example.com",
        "control_port": 9444,
        "base_certificate": _BASE_CERTIFICATE,
    }


def _identity():
    return NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="203.0.113.2",
        control_port=9444,
        certificate="/etc/hydra/node/node.crt",
        private_key="/etc/hydra/node/node.key",
        base_ca="/etc/hydra/node/base-ca.crt",
        base_fingerprint="a" * 64,
    )


def test_provision_entrypoint_derives_base_ip_and_starts_only_after_identity():
    identity = _identity()
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(_payload()))),
        patch.dict(node_provision.os.environ, {"SSH_CONNECTION": "203.0.113.2 50000 192.0.2.4 22"}),
        patch.object(node_provision, "provision_node_identity", return_value=identity) as provision,
        patch.object(
            node_provision.HOST,
            "systemd",
            side_effect=[CompletedProcess([], 0), CompletedProcess([], 0)],
        ) as systemd,
    ):
        assert node_provision.main() == 0

    provision.assert_called_once_with(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="203.0.113.2",
        control_address="node.example.com",
        control_port=9444,
        base_certificate=_BASE_CERTIFICATE.encode("ascii"),
        host=node_provision.HOST,
    )
    assert [call.args for call in systemd.call_args_list] == [
        ("enable", "hydra-node-control.service"),
        ("start", "hydra-node-control.service"),
    ]


def test_rotation_entrypoint_passes_only_the_ssh_peer_and_new_base_certificate():
    payload = {**_payload(), "action": "rotate"}
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(payload))),
        patch.dict(node_provision.os.environ, {"SSH_CONNECTION": "203.0.113.9 50000 192.0.2.4 22"}),
        patch.object(node_provision, "rotate_node_control_identity", return_value=_identity()) as rotate,
        patch.object(node_provision, "provision_node_identity") as provision,
    ):
        assert node_provision.main() == 0

    rotate.assert_called_once_with(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="203.0.113.9",
        control_address="node.example.com",
        control_port=9444,
        base_certificate=_BASE_CERTIFICATE.encode("ascii"),
        host=node_provision.HOST,
    )
    provision.assert_not_called()


def test_revoke_entrypoint_preserves_the_node_installation_marker():
    payload = {"action": "revoke", "node_id": "de-1"}
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(payload))),
        patch.dict(node_provision.os.environ, {}, clear=True),
        patch.object(node_provision, "revoke_node_control_identity") as revoke,
    ):
        assert node_provision.main() == 0

    revoke.assert_called_once_with(node_id="de-1", host=node_provision.HOST)


def test_provision_entrypoint_rejects_missing_ssh_peer_before_mutation():
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(_payload()))),
        patch.dict(node_provision.os.environ, {}, clear=True),
        patch.object(node_provision, "provision_node_identity") as provision,
        patch.object(node_provision.HOST, "systemd") as systemd,
    ):
        assert node_provision.main() == 2
    provision.assert_not_called()
    systemd.assert_not_called()


def test_uninstall_entrypoint_uses_application_uninstaller_only_for_matching_node():
    payload = {"action": "uninstall", "node_id": "de-1"}
    uninstall = Mock()
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(payload))),
        patch.object(node_provision, "load_node_identity", return_value=_identity(), create=True),
        patch.object(node_provision, "production_node_uninstall", uninstall),
    ):
        assert node_provision.main() == 0

    uninstall.assert_called_once_with()


def test_provision_entrypoint_reports_service_start_failure_without_claiming_success(capsys):
    with (
        patch.object(node_provision.sys, "stdin", io.StringIO(json.dumps(_payload()))),
        patch.dict(node_provision.os.environ, {"SSH_CONNECTION": "203.0.113.2 50000 192.0.2.4 22"}),
        patch.object(node_provision, "provision_node_identity", return_value=_identity()),
        patch.object(
            node_provision.HOST,
            "systemd",
            side_effect=[CompletedProcess([], 0), CompletedProcess([], 1)],
        ) as systemd,
    ):
        assert node_provision.main() == 2
    assert systemd.call_count == 2
    assert "provisioning failed" in capsys.readouterr().err.lower()
