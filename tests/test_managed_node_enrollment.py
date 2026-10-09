from __future__ import annotations

import time
from pathlib import Path
from subprocess import CompletedProcess
from typing import Literal, cast

import pytest

from hydra.contracts.managed_node_installation import InstallPlan, InstallRequest
from hydra.contracts.managed_node_models import NodeDefinition, ProtocolAssignment
from hydra.contracts.managed_node_observations import NodeSample
from hydra.core import state as state_backend
from hydra.core.host import HostBackend
from hydra.services.managed_nodes.askpass import request_password
from hydra.services.managed_nodes.credentials import ManagementCredentialStore, SshPasswordChannel, SshAuthError
from hydra.services.managed_nodes.enrollment import apply_management_firewall, remove_management_firewall
from hydra.services.managed_nodes.identity import create_certificate_pair
from hydra.services.managed_nodes.installation import resolve_managed_node_revision
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import OpenSshManagedNodeSSH, SshFacts, SshOperationError, _parse_listening_ports

_SHA = "a" * 40
_FINGERPRINT = "SHA256:" + "A" * 43


class StrictSsh:
    def __init__(self, *, existing=False, used_ports=frozenset(), fail_uninstall=False):
        self.facts = SshFacts("ubuntu", "24.04", 1000, True, existing, "198.51.100.8", used_ports, _FINGERPRINT)
        self.fail_uninstall = fail_uninstall
        self.calls: list[str] = []
        self.server_certificate = None
        self.reconcile: Literal["done", "retry", "unknown"] = "retry"

    def discover_host_key(self, address, port):
        assert address and port == 22
        return _FINGERPRINT

    def inspect(self, request, auth):
        self.calls.append("inspect")
        return self.facts

    def uninstall_existing(self, plan, auth):
        self.calls.append("uninstall_existing")
        if self.fail_uninstall:
            raise SshOperationError("existing-uninstall", "CLI uninstall returned failure", outcome_unknown=False)

    def bootstrap(self, plan, auth):
        self.calls.append("bootstrap")

    def provision_management(self, plan, base_certificate, auth):
        self.calls.append("provision")
        self.server_certificate, _ = create_certificate_pair(
            plan.definition.id, role="server", address=plan.definition.address
        )
        return self.server_certificate

    def read_public_certificate(self, plan, auth):
        self.calls.append("read-certificate")
        return self.server_certificate

    def remove_node(self, plan, auth):
        self.calls.append("remove")

    def reconcile_install_step(self, plan, operation, auth) -> Literal["done", "retry", "unknown"]:
        self.calls.append("reconcile:" + str(operation.active_step))
        return self.reconcile

    def reconcile_remove(self, plan, operation, auth) -> Literal["done", "retry", "unknown"]:
        self.calls.append("reconcile-remove")
        return "unknown"


class StrictManagementClient:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.deadlines: list[float] = []

    def state(self, deadline: float) -> NodeSample:
        self.deadlines.append(deadline)
        assert deadline > time.monotonic()
        return NodeSample(self.node_id, runtime={"management_api": "ready"})


class FirewallHost:
    def __init__(self, *, fail_insert_at: int | None = None):
        self.rules: dict[str, list[list[str]]] = {"iptables": [], "ip6tables": []}
        self.calls: list[list[str]] = []
        self.fail_insert_at = fail_insert_at
        self.insert_count = 0

    def which(self, executable: str) -> str:
        return executable

    def run(self, args, *, timeout=0, text=False, **_options):
        self.calls.append(list(args))
        executable, action = args[0], args[2]
        rules = self.rules[executable]
        if action == "-S":
            output = "".join(" ".join(rule) + "\n" for rule in rules)
            return CompletedProcess(args, 0, output, "")
        if action == "-I":
            self.insert_count += 1
            if self.insert_count == self.fail_insert_at:
                return CompletedProcess(args, 1, "", "injected firewall failure")
            index = int(args[4]) - 1
            rules.insert(index, ["-A", args[3], *args[5:]])
            return CompletedProcess(args, 0, "", "")
        if action == "-D":
            wanted = ["-A", args[3], *args[4:]]
            rules.remove(wanted)
            return CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected firewall operation: {args}")


def make_operations(tmp_path: Path, remote: StrictSsh, *, ids=None, client_factory_override=None):
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    credentials = ManagementCredentialStore(host=HostBackend(), root=tmp_path / "credentials")
    clients: list[StrictManagementClient] = []

    def client_factory(definition, files, server_certificate):
        client = StrictManagementClient(definition.id)
        clients.append(client)
        return client

    sequence = iter(ids or ("install-1", "install-2", "remove-1"))
    operations = ManagedNodeOperationsService(
        records=records,
        ssh=remote,
        credentials=credentials,
        revision_resolver=lambda branch: _SHA if branch == "dev" else "b" * 40,
        operation_id_factory=lambda: next(sequence),
        client_factory=client_factory_override or client_factory,
    )
    return operations, records, credentials, clients


def request(*, node_id="de-1", control_port=None, branch="dev"):
    return InstallRequest(
        id=node_id,
        name=node_id.upper(),
        address="203.0.113.4",
        ssh_user="operator",
        branch=branch,
        protocols=[ProtocolAssignment("vless", {"port": 443})],
        host_key_fingerprint=_FINGERPRINT,
        control_port=control_port,
    )


def test_revision_resolution_is_argv_bounded_and_rejects_unpinned_results():
    class RevisionHost:
        def __init__(self, output: str, returncode: int = 0):
            self.output = output
            self.returncode = returncode
            self.calls = []

        def run(self, args, *, timeout, text):
            self.calls.append((args, timeout, text))
            return CompletedProcess(args, self.returncode, self.output, "")

    host = RevisionHost(f"{_SHA}\trefs/heads/dev\n")
    assert resolve_managed_node_revision(cast(HostBackend, host), "dev", "https://example.invalid/hydra.git") == _SHA
    assert host.calls == [
        (["git", "ls-remote", "--exit-code", "https://example.invalid/hydra.git", "refs/heads/dev"], 20, True)
    ]

    with pytest.raises(ValueError, match="branch"):
        resolve_managed_node_revision(cast(HostBackend, host), "feature", "https://example.invalid/hydra.git")
    invalid = RevisionHost("not-a-revision\trefs/heads/dev\n")
    with pytest.raises(RuntimeError, match="invalid revision"):
        resolve_managed_node_revision(cast(HostBackend, invalid), "dev", "https://example.invalid/hydra.git")


def test_plan_pins_revision_once_and_auto_port_excludes_ssh_protocol_and_foreign_ports(tmp_path: Path):
    remote = StrictSsh(used_ports=frozenset({24443, 24444}))
    ops, records, _credentials, _clients = make_operations(tmp_path, remote)
    plan = ops.plan(request(), ssh_auth=None)
    assert plan.definition.revision == _SHA
    assert plan.definition.branch == "dev"
    assert plan.definition.control_port not in {22, 443, 24443, 24444}
    assert plan.host_key_fingerprint == _FINGERPRINT
    assert plan.source_address == "198.51.100.8"
    assert records.list_definitions() == []


def test_existing_install_requires_separate_consent_and_uninstall_failure_stops_before_bootstrap(tmp_path: Path):
    remote = StrictSsh(existing=True)
    ops, records, _credentials, _clients = make_operations(tmp_path, remote)
    plan = ops.plan(request(control_port=25555), ssh_auth=None)
    refused = ops.install(plan, ssh_auth=None, confirmed=True, reinstall_confirmed=False)
    assert refused.state == "failed"
    assert refused.error is not None and refused.error["stage"] == "consent"
    assert remote.calls == ["inspect"]
    assert records.find_definition("de-1") is None

    remote = StrictSsh(existing=True, fail_uninstall=True)
    ops, records, _credentials, _clients = make_operations(tmp_path / "failed", remote, ids=("install-failed",))
    plan = ops.plan(request(control_port=25555), ssh_auth=None)
    failed = ops.install(plan, ssh_auth=None, confirmed=True, reinstall_confirmed=True)
    assert failed.state == "failed"
    assert remote.calls == ["inspect", "uninstall_existing"]
    assert "bootstrap" not in remote.calls
    assert records.find_definition("de-1") is not None


def test_install_is_resumable_and_does_not_repeat_completed_remote_steps(tmp_path: Path):
    remote = StrictSsh(existing=True, used_ports=frozenset({24443}))
    ops, records, credentials, clients = make_operations(tmp_path, remote, ids=("install-known",))
    plan = ops.plan(request(control_port=25555), ssh_auth=None)
    first = ops.install(plan, ssh_auth=None, confirmed=True, reinstall_confirmed=True)
    assert first.state == "running"  # protocol/user apply belongs to the next owner
    assert first.error is not None and first.error["stage"] == "apply"
    assert remote.calls == ["inspect", "uninstall_existing", "bootstrap", "provision"]
    assert clients and clients[0].node_id == "de-1"
    assert credentials.client_files(plan.definition.identity_ref).private_key.exists()

    restarted, _records, _credentials, _clients = make_operations(tmp_path, remote, ids=("unused",))
    resumed = restarted.resume(first.id, ssh_auth=None)
    assert resumed.id == first.id and resumed.completed_steps == first.completed_steps
    assert remote.calls.count("bootstrap") == 1
    assert remote.calls.count("provision") == 1


class CrashAfterSshAction(StrictSsh):
    def __init__(self, crash_after: str, *, existing: bool):
        super().__init__(existing=existing)
        self.crash_after = crash_after
        self.installed = existing
        self.bootstrap_done = False
        self.action_counts: dict[str, int] = {}

    def _finish_action(self, step: str) -> None:
        self.action_counts[step] = self.action_counts.get(step, 0) + 1
        if self.crash_after == step and self.action_counts[step] == 1:
            raise SystemExit(17)

    def uninstall_existing(self, plan, auth):
        self.calls.append("uninstall_existing")
        self.installed = False
        self._finish_action("existing_uninstall")

    def bootstrap(self, plan, auth):
        self.calls.append("bootstrap")
        self.bootstrap_done = True
        self._finish_action("bootstrap")

    def provision_management(self, plan, base_certificate, auth):
        self.calls.append("provision")
        self.server_certificate = create_certificate_pair(
            plan.definition.id, role="server", address=plan.definition.address
        )[0]
        self._finish_action("management_identity")
        return self.server_certificate

    def reconcile_install_step(self, plan, operation, auth) -> Literal["done", "retry", "unknown"]:
        if operation.active_step == "existing_uninstall":
            return "done" if not self.installed else "retry"
        if operation.active_step == "bootstrap":
            return "done" if self.bootstrap_done else "retry"
        return "retry"


def test_process_restart_after_each_side_effect_resumes_from_persisted_step(tmp_path: Path):
    for index, step in enumerate(("existing_uninstall", "bootstrap", "management_identity", "management_verified")):
        root = tmp_path / step
        remote = CrashAfterSshAction(step, existing=step == "existing_uninstall")
        client_calls = 0

        class CrashManagementClient(StrictManagementClient):
            def state(self, deadline: float) -> NodeSample:
                nonlocal client_calls
                client_calls += 1
                if step == "management_verified" and client_calls == 1:
                    raise SystemExit(17)
                return super().state(deadline)

        def client_factory(definition, files, server_certificate):
            return CrashManagementClient(definition.id)

        service, records, _credentials, _clients = make_operations(
            root,
            remote,
            ids=(f"install-crash-{index}",),
            client_factory_override=client_factory,
        )
        node_id = f"de-{index + 1}"
        plan = service.plan(request(node_id=node_id, control_port=25555), ssh_auth=None)
        with pytest.raises(SystemExit):
            service.install(
                plan,
                ssh_auth=None,
                confirmed=True,
                reinstall_confirmed=step == "existing_uninstall",
            )
        interrupted = records.find_operation(f"install-crash-{index}")
        assert interrupted is not None and interrupted.active_step == step

        restarted, _records, _credentials, _clients = make_operations(
            root,
            remote,
            ids=("unused",),
            client_factory_override=client_factory,
        )
        result = restarted.resume(interrupted.id, ssh_auth=None)
        assert result.state == "running" and result.active_step is None
        assert step in result.completed_steps
        assert remote.action_counts.get(step, 0) <= 1
        if step == "management_identity":
            assert remote.calls.count("provision") == 1
        if step == "management_verified":
            assert client_calls == 2


def test_uncertain_bootstrap_result_requires_reconciliation_not_second_install(tmp_path: Path):
    class LostBootstrap(StrictSsh):
        def bootstrap(self, plan, auth):
            self.calls.append("bootstrap")
            raise SshOperationError("bootstrap", "connection lost", outcome_unknown=True)

    remote = LostBootstrap()
    ops, records, _credentials, _clients = make_operations(tmp_path, remote, ids=("install-uncertain",))
    plan = ops.plan(request(control_port=25555), ssh_auth=None)
    pending = ops.install(plan, ssh_auth=None, confirmed=True, reinstall_confirmed=False)
    assert pending.state == "recovery_required" and pending.active_step == "bootstrap"
    remote.reconcile = "unknown"
    resumed = ops.resume(pending.id, ssh_auth=None)
    assert resumed.state == "recovery_required"
    assert remote.calls.count("bootstrap") == 1
    assert records.find_operation(pending.id) is not None


def test_ss_inventory_reads_real_local_endpoint_and_nonroot_templates_use_sudo_executable():
    assert _parse_listening_ports("tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nudp UNCONN 0 0 [::]:8443 [::]:*\n") == {
        443,
        8443,
    }
    plan = InstallPlan(
        definition=NodeDefinition(
            "de-1",
            "DE-1",
            "203.0.113.4",
            "operator",
            "dev",
            _SHA,
            25555,
            [ProtocolAssignment("vless", {"port": 443})],
            "managed-node/de-1",
            22,
        ),
        existing_installation=False,
        steps=["bootstrap"],
        host_key_fingerprint=_FINGERPRINT,
        source_address="198.51.100.8",
        use_sudo=True,
    )
    assert OpenSshManagedNodeSSH.remote_command_for(plan, "uninstall") == (
        "cd /opt/hydra && sudo -n /opt/hydra/.venv/bin/python -m hydra.cli uninstall --yes"
    )
    assert "sudo cd" not in OpenSshManagedNodeSSH.remote_command_for(plan, "provision")


def test_management_firewall_is_source_scoped_ordered_idempotent_and_removed_only_by_node_id():
    host = FirewallHost()
    host_backend = cast(HostBackend, host)
    apply_management_firewall(host=host_backend, source_ip="198.51.100.8", control_port=24443, node_id="de-1")
    first_rules = [list(rule) for rule in host.rules["iptables"]]
    assert len(first_rules) == 2
    assert "198.51.100.8" in first_rules[0]
    assert "ACCEPT" in first_rules[0]
    assert "DROP" in first_rules[1]
    assert "24443" in first_rules[0] and "24443" in first_rules[1]

    apply_management_firewall(host=host_backend, source_ip="198.51.100.8", control_port=24443, node_id="de-1")
    assert host.rules["iptables"] == first_rules
    remove_management_firewall(host=host_backend, node_id="de-1", allowed_source_ips=["198.51.100.8"])
    assert host.rules["iptables"] == []


def test_management_firewall_failure_rolls_back_only_its_rules():
    host = FirewallHost(fail_insert_at=2)
    unmanaged = ["-A", "INPUT", "-p", "tcp", "--dport", "24443", "-j", "ACCEPT"]
    host.rules["iptables"].append(unmanaged)

    with pytest.raises(RuntimeError, match="management firewall command failed"):
        apply_management_firewall(
            host=cast(HostBackend, host),
            source_ip="198.51.100.8",
            control_port=24443,
            node_id="de-1",
        )

    assert host.rules["iptables"] == [unmanaged]


def test_management_credential_cleanup_is_scoped_to_its_identity_ref(tmp_path: Path):
    store = ManagementCredentialStore(host=HostBackend(), root=tmp_path / "credentials")
    node_ref = "managed-node/de-1"
    sibling_ref = "managed-node/uk-1"
    store.ensure_client_identity(node_ref)
    node_server, _ = create_certificate_pair("de-1", role="server", address="203.0.113.4")
    node_files = store.store_server_certificate(node_ref, node_server, node_id="de-1", address="203.0.113.4")
    store.ensure_client_identity(sibling_ref)
    sibling_server, _ = create_certificate_pair("uk-1", role="server", address="203.0.113.5")
    sibling_files = store.store_server_certificate(sibling_ref, sibling_server, node_id="uk-1", address="203.0.113.5")
    unrelated = tmp_path / "credentials" / "managed-node" / "de-1.backup.key"
    unrelated.write_bytes(b"not an owned credential")

    store.cleanup(node_ref)

    assert not node_files.exists()
    assert not (tmp_path / "credentials" / "managed-node" / "de-1.client.crt").exists()
    assert not (tmp_path / "credentials" / "managed-node" / "de-1.client.key").exists()
    assert sibling_files.exists()
    assert store.client_files(sibling_ref).private_key.exists()
    assert unrelated.read_bytes() == b"not an owned credential"


def test_password_channel_helper_quotes_package_and_interpreter_paths(tmp_path: Path, monkeypatch):
    import hydra
    import shlex

    package_root = tmp_path / "hydra package"
    interpreter = tmp_path / "python interpreter"
    monkeypatch.setattr(hydra, "__file__", str(package_root / "hydra" / "__init__.py"))
    channel = SshPasswordChannel("sensitive-passphrase").start()
    try:
        helper = Path(channel.environment(interpreter=str(interpreter))["SSH_ASKPASS"])
        source = helper.read_text(encoding="utf-8")
        assert f"export PYTHONPATH={shlex.quote(str(package_root))}" in source
        assert f"exec {shlex.quote(str(interpreter))} -m hydra.services.managed_nodes.askpass" in source
        assert "sensitive-passphrase" not in source
    finally:
        channel.close()


def test_password_channel_survives_idle_and_multiple_prompts_until_explicit_close(tmp_path: Path):
    password = "sensitive-passphrase"
    auth = SshPasswordChannel(password).start()
    environment = auth.environment()
    helper = Path(environment["SSH_ASKPASS"])
    assert password not in repr(auth) and password not in repr(environment)
    assert password not in helper.read_text(encoding="utf-8")
    time.sleep(0.6)
    assert request_password(environment) == password
    assert request_password(environment) == password
    auth.close()
    assert not auth.is_open and not helper.exists()
    assert auth.password == ""
    with pytest.raises(SshAuthError):
        auth.environment()
