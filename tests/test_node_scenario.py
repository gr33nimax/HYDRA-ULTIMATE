"""The operator's node scenario end to end at the service boundary.

Install order, a visible ID that never touches technical identity, one full sync, and
three different endings: full removal, withdrawal from subscriptions with a real purge,
and detach without cleanup. Host effects stay injected, so this runs without a VPS.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from hydra.core.host import HostBackend

from hydra.contracts.node_export import NodeClientExport, NodeClientExportUser, NodeClientProfile
from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState, User
from hydra.core.state_format import STATE_FORMAT_VERSION, pack_state_document, unpack_state_document
from hydra.core.state_nodes import (
    MANAGEMENT_WITHDRAWN,
    NodeConfig,
    validate_nodes,
)
from hydra.services.nodes.installer import (
    checked_ssh_user,
    remote_command,
    ssh_target,
)
from hydra.services.nodes.manager import NodeManager
from hydra.services.nodes.control_client import NodeContactError
from hydra.services.nodes.observation import NodeObservationStore
from hydra.services.nodes.reconciler import NodeSnapshotReconciler
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.nodes.ssh_auth import SshPasswordAuth
from hydra.core import state as state_module


class FakeControlClient:
    """A node that answers honestly and records what it was told to apply."""

    def __init__(self, node_id: str = "uk-1") -> None:
        self.node_id = node_id
        self.applied = []
        self.exported = 0

    def health(self):
        return {
            "ok": True,
            "node_id": self.node_id,
            "contract_version": 5,
            "revision": "a" * 40,
        }

    def apply(self, snapshot):
        self.applied.append(snapshot)
        return {"generation": snapshot.generation, "already_applied": False}

    def export(self):
        self.exported += 1
        generation = self.applied[-1].generation
        if self.applied[-1].protocols:
            profiles = (NodeClientProfile(protocol="vless", profile="", links=("vless://edge",)),)
        else:
            profiles = ()
        return NodeClientExport(
            node_id=self.node_id,
            generation=generation,
            users={"u1": NodeClientExportUser(uuid="u1", profiles=profiles)},
        )


def _state(*, node: NodeConfig | None = None) -> NodeConfig:
    """Reset desired state through the guarded writer, not a raw save."""

    def reset(state: AppState) -> None:
        state.users = [User(email="alice@example.com", uuid="u1")]
        state.nodes = [node or NodeConfig(id="uk-1", name="UK", address="203.0.113.7")]

    state_module.update_state(reset)
    return state_module.load_state().nodes[0]


def _with_protocol(node_id: str, name: str = "vless") -> None:
    def install(state: AppState) -> None:
        for node in state.nodes:
            if node.id == node_id:
                node.protocols[name] = NodeProtocolSpec(enabled=True, port=443)

    state_module.update_state(install)


def _manager(tmp_path, client, **options) -> NodeManager:
    return NodeManager(
        state_reader=state_module.load_state,
        state_updater=state_module.update_state,
        client_for=lambda node: client,
        snapshot_store=NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports"),
        observations=NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json"),
        **options,
    )


# ── visible identity ────────────────────────────────────────────────────────


def test_visible_id_and_management_survive_the_current_state_format():
    _state()

    def rename(state: AppState) -> None:
        node = state.nodes[0]
        node.display_id = "uk-visible"
        node.management = MANAGEMENT_WITHDRAWN
        node.ssh_user = "deploy"

    state_module.update_state(rename)

    reloaded = state_module.load_state().nodes[0]
    assert reloaded.display_id == "uk-visible"
    assert reloaded.label == "uk-visible"
    assert reloaded.withdrawn is True
    assert reloaded.ssh_user == "deploy"

    document = pack_state_document(
        unpack_state_document({"format_version": 1, "revision": 0, "core": {}, "features": {}})
    )
    assert document["format_version"] == STATE_FORMAT_VERSION == 1


def test_two_nodes_cannot_share_a_visible_id():
    with pytest.raises(ValueError, match="share the visible id"):
        validate_nodes(
            [
                NodeConfig(id="uk-1", name="UK", address="203.0.113.7", display_id="edge"),
                NodeConfig(id="fi-1", name="FI", address="203.0.113.8", display_id="EDGE"),
            ]
        )


def test_appearance_change_is_offline_and_leaves_technical_identity_alone(tmp_path):
    node = _state()
    manager = _manager(tmp_path, FakeControlClient())

    renamed = manager.set_appearance(node.id, display_id="uk-visible", name="United Kingdom")

    assert renamed.label == "uk-visible"
    saved = state_module.load_state().nodes[0]
    assert saved.id == "uk-1"
    assert saved.control_fingerprint == ""
    assert saved.generation == 0


# ── withdrawal and return ───────────────────────────────────────────────────


def test_withdraw_purges_the_node_runtime_and_stops_publication(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    published = manager.refresh(node.id)
    assert published.status == "published"
    stored = list((tmp_path / "exports").rglob("*.json"))
    assert stored

    result = manager.withdraw_node(node.id, confirmed=True)

    assert result["status"] == "withdrawn"
    assert result["remote_cleanup"] is True
    saved = state_module.load_state().nodes[0]
    assert saved.withdrawn is True
    assert saved.published_generation == 0 and saved.published_digest == ""
    assert manager.published_export(state_module.load_state(), node.id) is None
    assert client.applied[-1].users == ()
    assert client.applied[-1].protocols == {}
    assert list((tmp_path / "exports").rglob("*.json")) == []


def test_the_next_cycle_does_not_restore_a_withdrawn_node(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    manager.refresh(node.id)
    manager.withdraw_node(node.id, confirmed=True)
    applied_after_withdraw = len(client.applied)

    assert manager.refresh(node.id).status == "withdrawn"
    assert manager.refresh(node.id).status == "withdrawn"
    assert len(client.applied) == applied_after_withdraw
    assert manager.published_export(state_module.load_state(), node.id) is None
    assert client.exported == 1


def test_withdraw_without_connection_still_stops_publication_and_reports_pending_purge(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)
    manager.refresh(node.id)

    class Offline(FakeControlClient):
        def health(self):
            raise OSError("offline")

    offline = _manager(tmp_path, Offline())
    result = offline.withdraw_node(node.id, confirmed=True)

    assert result["remote_cleanup"] is False
    assert result["error"] == "OSError"
    saved = state_module.load_state().nodes[0]
    assert saved.withdrawn is True
    assert saved.published_generation == 0


def test_return_to_service_republishes_fresh_profiles(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    manager.refresh(node.id)
    manager.withdraw_node(node.id, confirmed=True)
    restored = manager.restore_node(node.id)

    assert restored.status == "published"
    assert restored.coverage == {"vless": 1}
    saved = state_module.load_state().nodes[0]
    assert saved.withdrawn is False
    assert saved.published_generation > 0


def test_withdraw_requires_explicit_confirmation(tmp_path):
    node = _state()
    manager = _manager(tmp_path, FakeControlClient())
    with pytest.raises(ValueError, match="explicit confirmation"):
        manager.withdraw_node(node.id, confirmed=False)
    assert state_module.load_state().nodes[0].withdrawn is False


# ── SSH account and password channel ────────────────────────────────────────


def test_ssh_target_and_sudo_wrapper_use_the_configured_account():
    assert ssh_target("root", "203.0.113.7") == "root@203.0.113.7"
    assert ssh_target("deploy", "2001:db8::1") == "deploy@[2001:db8::1]"
    assert remote_command("root", "true") == "true"
    assert remote_command("deploy", "true") == "sudo -n true"
    assert checked_ssh_user("deploy") == "deploy"
    for bad in ("", "  ", "root;rm -rf /", "a" * 65, 5):
        with pytest.raises(ValueError):
            checked_ssh_user(bad)


def test_password_channel_hands_over_the_secret_without_leaking_it():
    with SshPasswordAuth("s3cret phrase") as auth:
        environment = auth.environment(interpreter=sys.executable)
        assert "s3cret" not in " ".join(environment.values())
        result = subprocess.run(
            [sys.executable, "-m", "hydra.entrypoints.ssh_askpass"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "s3cret phrase"

        wrong = dict(environment)
        wrong["HYDRA_ASKPASS_TOKEN"] = "not-the-token"
        refused = subprocess.run(
            [sys.executable, "-m", "hydra.entrypoints.ssh_askpass"],
            env=wrong,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert refused.returncode == 1
        assert refused.stdout == ""
        helper = environment["SSH_ASKPASS"]

    closed = subprocess.run(
        [sys.executable, "-m", "hydra.entrypoints.ssh_askpass"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert closed.returncode == 1


def test_installer_streams_the_script_to_the_configured_account_with_sudo(tmp_path):
    from hydra.services.nodes import installer

    calls: list[tuple[list[str], dict]] = []

    class FakeHost:
        def run(self, args, **kwargs):
            calls.append((list(args), kwargs))
            if args[0] == "ssh-keyscan":
                return subprocess.CompletedProcess(args, 0, "node.example.com ssh-ed25519 AAAA\n", "")
            if args[0] == "ssh-keygen":
                return subprocess.CompletedProcess(args, 0, "2048 SHA256:abc node.example.com (ED25519)\n", "")
            if args[0] == "ssh" and args[-1].startswith("id -u"):
                return subprocess.CompletedProcess(args, 0, "1000\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        def ensure_directory(self, path, mode=0o700):
            path.mkdir(parents=True, exist_ok=True)

        def atomic_write(self, path, content, mode=0o600):
            path.write_text(content, encoding="utf-8")

    with SshPasswordAuth("pw") as auth:
        fingerprint = installer.install_node(
            host=cast(HostBackend, FakeHost()),
            script="echo install\n",
            known_hosts_root=tmp_path / "ssh",
            node_id="uk-1",
            address="node.example.com",
            ssh_port=22,
            branch="main",
            revision="a" * 40,
            confirm_fingerprint=lambda value: True,
            ssh_user="deploy",
            auth=auth,
        )
    assert fingerprint == "SHA256:abc"

    targets = [args[-2] for args, _ in calls if args[0] == "ssh" and not args[-1].startswith("id -u")]
    assert targets == ["deploy@node.example.com"]
    streamed = [args[-1] for args, _ in calls if args[0] == "ssh" and not args[-1].startswith("id -u")]
    assert streamed[0].startswith("sudo -n HYDRA_ROLE=node")
    privileged = [kwargs for args, kwargs in calls if args[0] == "ssh"]
    assert all("pw" not in str(kwargs.get("env", {})) for kwargs in privileged)
    assert all(kwargs.get("env", {}).get("SSH_ASKPASS") for kwargs in privileged)


def test_manager_reports_when_the_installer_refuses_an_unprivileged_account(tmp_path):
    node = _state()
    manager = _manager(tmp_path, FakeControlClient())

    class Refusing:
        """A provisioning port that refuses the account before touching the VPS."""

        def resolve_revision(self, branch: str) -> str:
            return "a" * 40

        def install(self, **kwargs):
            raise PermissionError("SSH account deploy cannot gain root without a password")

        def provision_control_identity(self, **kwargs):
            raise AssertionError("provisioning must not run after a refused install")

    manager.bootstrap = Refusing()
    manager.uninstall_remote = lambda node: None
    manager.forget_node_credentials = lambda node_id: None

    candidate = NodeConfig(id="fi-1", address="203.0.113.9", ssh_user="deploy", revision="a" * 40)
    with pytest.raises(PermissionError):
        manager.add_node(
            candidate,
            base_url="https://base.example.com",
            confirm_fingerprint=lambda value: True,
        )
    assert [item.id for item in state_module.load_state().nodes] == [node.id]


def test_full_removal_and_detach_stay_distinct(tmp_path):
    node = _state()
    removed: list[str] = []
    forgotten: list[str] = []
    manager = _manager(
        tmp_path,
        FakeControlClient(),
        uninstall_remote=lambda item: removed.append(item.id),
        forget_node_credentials=lambda node_id: forgotten.append(node_id),
    )

    detached = manager.detach_node(node.id, confirmed=True)
    assert detached["remote_cleanup"] is False
    assert removed == []
    assert forgotten == ["uk-1"]

    _state()
    manager = _manager(
        tmp_path,
        FakeControlClient(),
        uninstall_remote=lambda item: removed.append(item.id),
        forget_node_credentials=lambda node_id: forgotten.append(node_id),
    )
    result = manager.remove_node(node.id, confirmed=True)
    assert result["status"] == "removed"
    assert removed == ["uk-1"]


def test_status_is_recorded_from_a_real_contact_not_from_opening_the_menu(tmp_path):
    node = _state()
    _with_protocol(node.id)
    manager = _manager(tmp_path, FakeControlClient())

    manager.refresh(node.id)

    observation = manager.observations()["uk-1"]
    assert observation.control == "ok"
    assert observation.published_generation == 1
    assert datetime.fromisoformat(observation.checked_at).tzinfo is not None


# ── publication freshness ───────────────────────────────────────────────────


def test_an_updated_node_republishes_even_when_settings_did_not_change(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    first = manager.refresh(node.id)
    assert first.status == "published"
    assert first.installed_revision == "a" * 40

    # The node was updated: same desired configuration, different build.
    client.health = lambda: {
        "ok": True,
        "node_id": client.node_id,
        "contract_version": 5,
        "revision": "b" * 40,
    }
    refreshed = manager.refresh(node.id)

    assert refreshed.status == "published"
    assert refreshed.installed_revision == "b" * 40
    assert refreshed.generation > first.generation
    assert client.exported == 2


def test_an_unchanged_node_with_an_intact_bundle_is_not_re_exported(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)

    manager.refresh(node.id)
    again = manager.refresh(node.id)

    assert again.status == "unchanged"
    assert again.sha256
    assert client.exported == 1


def test_a_missing_or_unreadable_bundle_is_rebuilt_from_the_node(tmp_path):
    node = _state()
    _with_protocol(node.id)
    client = FakeControlClient()
    manager = _manager(tmp_path, client)
    manager.refresh(node.id)

    for path in (tmp_path / "exports").rglob("*.json"):
        path.write_text("{not json", encoding="utf-8")

    rebuilt = manager.refresh(node.id)

    assert rebuilt.status == "published"
    assert client.exported == 2
    assert manager.published_export(state_module.load_state(), node.id) is not None


# ── managed SSH key for later cleanup ───────────────────────────────────────


def test_managed_key_is_created_once_with_a_restrictive_mode(tmp_path):
    from hydra.services.nodes import ssh_keys

    written: list[tuple[Path, int]] = []

    class FakeHost:
        def atomic_write(self, path, content, mode=0o600):
            written.append((Path(path), mode))
            Path(path).write_bytes(content if isinstance(content, bytes) else content.encode())

    directory = tmp_path / "credentials" / "uk-1"
    directory.mkdir(parents=True)
    host = cast(HostBackend, FakeHost())
    first = ssh_keys.ensure_managed_keypair(host=host, directory=directory, node_id="uk-1")
    second = ssh_keys.ensure_managed_keypair(host=host, directory=directory, node_id="uk-1")

    assert first.public_line == second.public_line
    assert first.tag == "hydra-managed:uk-1"
    assert first.public_line.endswith("hydra-managed:uk-1")
    # Written once, private, and never regenerated on the next enrollment.
    assert written == [(first.private_key, 0o600)]


def test_managed_key_commands_never_touch_other_keys():
    from hydra.services.nodes import ssh_keys

    install = ssh_keys.remote_install_command("hydra-managed:uk-1", "ssh-ed25519 AAAA hydra-managed:uk-1")
    assert "grep -qF hydra-managed:uk-1" in install
    assert '>> "$HOME/.ssh/authorized_keys"' in install

    remove = ssh_keys.remote_remove_command("hydra-managed:uk-1")
    assert "grep -vF hydra-managed:uk-1" in remove
    assert "rm " not in remove
    assert ssh_keys.tagged_authorized_key_line("ssh-ed25519 AAAA hydra-managed:uk-1", tag="hydra-managed:uk-1")
    assert not ssh_keys.tagged_authorized_key_line("ssh-ed25519 AAAA someone@laptop", tag="hydra-managed:uk-1")


def test_cleanup_uses_the_managed_key_when_it_exists(tmp_path):
    from hydra.services.nodes.ssh_keys import managed_key_file

    directory = tmp_path / "credentials" / "uk-1"
    directory.mkdir(parents=True)
    assert managed_key_file(tmp_path / "credentials", "uk-1") is None
    (directory / "managed-ssh.key").write_text("key", encoding="utf-8")
    assert managed_key_file(tmp_path / "credentials", "uk-1") == directory / "managed-ssh.key"


def test_a_failed_remote_key_install_reports_and_keeps_the_same_key(tmp_path):
    from hydra.services.nodes import ssh_keys

    class RefusingHost:
        def ensure_directory(self, path, mode=0o700):
            path.mkdir(parents=True, exist_ok=True)

        def atomic_write(self, path, content, mode=0o600):
            path.write_bytes(content if isinstance(content, bytes) else content.encode())

        def run(self, args, **kwargs):
            return subprocess.CompletedProcess(args, 255, "", "ssh: refused")

    known_hosts_root = tmp_path / "ssh"
    (known_hosts_root / "uk-1").mkdir(parents=True)
    (known_hosts_root / "uk-1" / "known_hosts").write_text("host key", encoding="utf-8")
    host = cast(HostBackend, RefusingHost())

    with pytest.raises(RuntimeError, match="managed key installation"):
        ssh_keys.install_managed_key(
            host=host,
            credentials_root=tmp_path / "credentials",
            known_hosts_root=known_hosts_root,
            connection_flags=lambda port, known, scp=False: ["-p", str(port)],
            node_id="uk-1",
            address="203.0.113.7",
            ssh_port=22,
            ssh_user="deploy",
        )

    # The key stays local and stable, so a retry authorizes the same key instead of
    # leaving a second one behind on the node.
    key = ssh_keys.managed_key_file(tmp_path / "credentials", "uk-1")
    assert key is not None
    again = ssh_keys.ensure_managed_keypair(host=host, directory=key.parent, node_id="uk-1")
    assert again.public_line.endswith("hydra-managed:uk-1")


def test_a_failed_operation_survives_a_restart_of_the_management_process(tmp_path):
    """The outcome is durable: reopening the menu must not look like a fresh node."""
    node = _state()
    _with_protocol(node.id)

    class Offline(FakeControlClient):
        def health(self):
            raise NodeContactError("offline")

    first = _manager(tmp_path, Offline())
    with pytest.raises(NodeContactError):
        first.refresh(node.id)

    # A new process, the same observation store: the failure is still the fact.
    second = _manager(tmp_path, FakeControlClient())
    recorded = second.observations()["uk-1"]
    assert recorded.control == "error"
    assert recorded.stage == "connect"
    assert recorded.checked_at


def test_a_retry_after_a_lost_response_does_not_repeat_the_node_side_effect(tmp_path):
    """The node answers `already_applied`, so the base retries without a second apply."""
    node = _state()
    _with_protocol(node.id)

    class LostOnce(FakeControlClient):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.lost = False

        def apply(self, snapshot):
            self.applied.append(snapshot)
            if not self.lost:
                self.lost = True
                raise OSError("lost response")
            return {"generation": snapshot.generation, "already_applied": True}

    client = LostOnce()
    manager = _manager(tmp_path, client)
    with pytest.raises(OSError, match="lost response"):
        manager.refresh(node.id)

    result = manager.refresh(node.id)

    assert result.status == "published"
    # Both attempts carried the same generation: the node was never asked to apply two.
    assert {snapshot.generation for snapshot in client.applied} == {result.generation}
