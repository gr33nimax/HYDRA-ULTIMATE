import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from hydra.core.host import HostBackend
from hydra.contracts.node_validation import NODE_CONTRACT_VERSION
import hydra.services.nodes.bootstrap as bootstrap_module
from hydra.services.nodes.bootstrap import NodeBootstrap
from hydra.services.nodes.credentials import cleanup_node_credentials, generate_control_certificate
from hydra.services.nodes.installer import uninstall_node


@pytest.fixture
def healthy_control_probe(monkeypatch):
    class HealthyProbe:
        def __init__(self, **kwargs):
            self.arguments = kwargs

        def health(self):
            return {"ok": True, "node_id": "de-1", "contract_version": NODE_CONTRACT_VERSION}

    monkeypatch.setattr(bootstrap_module, "NodeControlClient", HealthyProbe, raising=False)


def _bootstrap(host, tmp_path):
    known_hosts = tmp_path / "ssh" / "de-1" / "known_hosts"
    host.atomic_write(known_hosts, "node-key\n", mode=0o600)
    return NodeBootstrap(
        host=host,
        script="install",
        known_hosts_root=tmp_path / "ssh",
        credentials_root=tmp_path / "credentials",
    )


def test_bootstrap_provisions_credentials_over_pinned_ssh_without_sending_private_key(
    tmp_path,
    monkeypatch,
):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)

    credentials = bootstrap.provision_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )

    assert credentials.node_fingerprint == node_certificate.fingerprint
    assert credentials.node_certificate.read_bytes() == node_certificate.certificate
    assert credentials.client_certificate.exists()
    assert credentials.client_private_key.exists()
    request = json.loads(calls[0][1]["input"])
    assert set(request) == {"node_id", "base_url", "control_address", "control_port", "base_certificate"}
    assert "private_key" not in request
    assert credentials.client_private_key.read_bytes() not in calls[0][1]["input"].encode()
    assert calls[0][0][0] == "ssh"
    assert "BatchMode=no" in calls[0][0]
    assert "StrictHostKeyChecking=yes" in calls[0][0]
    assert "hydra.entrypoints.node_provision" in calls[0][0][-1]
    assert calls[1][0][0] == "scp"
    assert "StrictHostKeyChecking=yes" in calls[1][0]
    assert calls[1][0][-2] == "root@node.example.com:/etc/hydra/node/node.crt"
    certificate = x509.load_pem_x509_certificate(credentials.node_certificate.read_bytes())
    assert certificate.fingerprint(hashes.SHA256()).hex() == (credentials.node_fingerprint)


def test_bootstrap_rotates_both_mtls_identities_and_persists_the_new_pair(
    tmp_path,
    monkeypatch,
    healthy_control_probe,
):
    host = HostBackend()
    initial_node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    rotated_node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    calls = []
    scp_certificates = iter((initial_node_certificate.certificate, rotated_node_certificate.certificate))

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "scp":
            Path(args[-1]).write_bytes(next(scp_certificates))
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)
    original = bootstrap.provision_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )
    original_certificate = original.client_certificate.read_bytes()

    rotated = bootstrap.rotate_control_credentials(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )

    rotate_request = json.loads(calls[2][1]["input"])
    assert rotate_request["action"] == "rotate"
    assert set(rotate_request) == {
        "action",
        "node_id",
        "base_url",
        "control_address",
        "control_port",
        "base_certificate",
    }
    assert rotate_request["base_certificate"].encode() != original_certificate
    assert "private_key" not in rotate_request
    assert rotated.base_fingerprint != original.base_fingerprint
    assert rotated.node_fingerprint == rotated_node_certificate.fingerprint
    assert rotated.node_fingerprint != original.node_fingerprint == initial_node_certificate.fingerprint
    assert rotated.client_private_key.read_bytes() not in calls[2][1]["input"].encode()
    assert bootstrap.load_control_credentials("de-1", address="node.example.com") == rotated
    assert not (tmp_path / "credentials" / "de-1" / "base-client.pending.crt").exists()
    assert (tmp_path / "credentials" / "de-1" / "base-client.active").read_text().strip() == rotated.base_fingerprint


def test_rotation_retry_reuses_staged_certificate_after_ssh_outcome_is_unknown(
    tmp_path,
    monkeypatch,
    healthy_control_probe,
):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    requests = []
    ssh_results = iter((1, 0))

    def fake_run(args, **kwargs):
        if args[0] == "ssh":
            requests.append(json.loads(kwargs["input"]))
            return CompletedProcess(args, next(ssh_results), stdout="", stderr="")
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)
    arguments = {
        "node_id": "de-1",
        "address": "node.example.com",
        "ssh_port": 2222,
        "base_url": "https://base.example.com:9444",
        "control_port": 9444,
    }

    with pytest.raises(RuntimeError, match="rotation failed"):
        bootstrap.rotate_control_credentials(**arguments)
    result = bootstrap.rotate_control_credentials(**arguments)

    assert requests[0]["base_certificate"] == requests[1]["base_certificate"]
    assert result.base_fingerprint


def test_rotation_does_not_activate_pending_credentials_without_mtls_health(tmp_path, monkeypatch):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")

    def fake_run(args, **kwargs):
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    class UnhealthyProbe:
        def __init__(self, **kwargs):
            pass

        def health(self):
            return {"ok": False, "node_id": "de-1", "contract_version": NODE_CONTRACT_VERSION}

    monkeypatch.setattr(host, "run", fake_run)
    monkeypatch.setattr(bootstrap_module, "NodeControlClient", UnhealthyProbe, raising=False)
    bootstrap = _bootstrap(host, tmp_path)

    with pytest.raises(RuntimeError, match="mTLS health check"):
        bootstrap.rotate_control_credentials(
            node_id="de-1",
            address="node.example.com",
            ssh_port=2222,
            base_url="https://base.example.com:9444",
            control_port=9444,
        )

    directory = tmp_path / "credentials" / "de-1"
    assert (directory / "base-client.pending.crt").exists()
    assert not (directory / "base-client.active").exists()


def test_revoke_uses_pinned_ssh_and_deletes_local_control_credentials_only_after_success(
    tmp_path,
    monkeypatch,
):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)
    credentials = bootstrap.provision_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )

    bootstrap.revoke_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
    )

    revoke_request = json.loads(calls[2][1]["input"])
    assert revoke_request == {"action": "revoke", "node_id": "de-1"}
    assert "StrictHostKeyChecking=yes" in calls[2][0]
    assert not credentials.client_certificate.exists()
    assert not credentials.client_private_key.exists()
    assert not credentials.node_certificate.exists()
    assert (tmp_path / "ssh" / "de-1" / "known_hosts").exists()


def test_revoke_removes_versioned_rotated_private_key(tmp_path, monkeypatch, healthy_control_probe):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")

    def fake_run(args, **kwargs):
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)
    credentials = bootstrap.rotate_control_credentials(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )
    directory = tmp_path / "credentials" / "de-1"
    assert credentials.client_private_key.exists()

    bootstrap.revoke_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
    )

    assert not credentials.client_private_key.exists()
    assert not credentials.client_certificate.exists()
    assert not (directory / "base-client.active").exists()


def test_revoke_failure_keeps_base_credentials_available_for_retry(tmp_path, monkeypatch):
    host = HostBackend()
    node_certificate = generate_control_certificate("de-1", role="server", address="node.example.com")
    ssh_results = iter((0, 1))

    def fake_run(args, **kwargs):
        if args[0] == "ssh":
            return CompletedProcess(args, next(ssh_results), stdout="", stderr="")
        if args[0] == "scp":
            Path(args[-1]).write_bytes(node_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)
    credentials = bootstrap.provision_control_identity(
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
        base_url="https://base.example.com:9444",
        control_port=9444,
    )

    with pytest.raises(RuntimeError, match="revocation failed"):
        bootstrap.revoke_control_identity(
            node_id="de-1",
            address="node.example.com",
            ssh_port=2222,
        )

    assert credentials.client_certificate.exists()
    assert credentials.client_private_key.exists()


def test_bootstrap_refuses_control_provisioning_without_a_pinned_ssh_host(tmp_path):
    host = HostBackend()
    bootstrap = NodeBootstrap(
        host=host,
        script="install",
        known_hosts_root=tmp_path / "ssh",
        credentials_root=tmp_path / "credentials",
    )

    with pytest.raises(RuntimeError, match="host key is not pinned"):
        bootstrap.provision_control_identity(
            node_id="de-1",
            address="node.example.com",
            ssh_port=22,
            base_url="https://base.example.com:9444",
            control_port=9444,
        )

    assert not (tmp_path / "credentials" / "de-1").exists()


def test_bootstrap_rejects_server_certificate_for_another_node(tmp_path, monkeypatch):
    host = HostBackend()
    wrong_certificate = generate_control_certificate("other-node", role="server", address="node.example.com")

    def fake_run(args, **kwargs):
        if args[0] == "scp":
            Path(args[-1]).write_bytes(wrong_certificate.certificate)
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    bootstrap = _bootstrap(host, tmp_path)

    with pytest.raises(ValueError, match="control certificate does not match its node role"):
        bootstrap.provision_control_identity(
            node_id="de-1",
            address="node.example.com",
            ssh_port=2222,
            base_url="https://base.example.com:9444",
            control_port=9444,
        )

    credentials_directory = tmp_path / "credentials" / "de-1"
    assert not (credentials_directory / "node.crt").exists()
    assert not (credentials_directory / ".node.crt.pending").exists()


def test_uninstall_node_uses_pinned_ssh_and_forgets_local_credentials_only_after_success(
    tmp_path,
    monkeypatch,
):
    host = HostBackend()
    bootstrap = _bootstrap(host, tmp_path)
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "run", fake_run)
    credentials = tmp_path / "credentials" / "de-1"
    credentials.mkdir(parents=True)
    private_key = credentials / "base-client.key"
    private_key.write_text("private", encoding="utf-8")
    known_hosts = tmp_path / "ssh" / "de-1" / "known_hosts"

    uninstall_node(
        host=host,
        known_hosts_root=bootstrap.known_hosts_root,
        node_id="de-1",
        address="node.example.com",
        ssh_port=2222,
    )

    assert private_key.exists()
    assert known_hosts.exists()
    assert calls[0][0][0] == "ssh"
    assert "StrictHostKeyChecking=yes" in calls[0][0]
    assert json.loads(calls[0][1]["input"]) == {"action": "uninstall", "node_id": "de-1"}

    cleanup_node_credentials(
        host=host,
        credentials_root=bootstrap.credentials_root,
        known_hosts_root=bootstrap.known_hosts_root,
        node_id="de-1",
        forget_host_key=True,
    )

    assert not private_key.exists()
    assert not known_hosts.exists()
