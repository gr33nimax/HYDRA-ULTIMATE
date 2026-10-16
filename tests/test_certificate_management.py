"""Local certificate maintenance with isolated files and an injected fake host."""

from __future__ import annotations

import copy
import shutil
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, PluginState
from hydra.services.certificate_audit import CertificateStatus
from hydra.services.certificate_files import CertificateFiles
from hydra.services.certificate_infrastructure import CertificateInfrastructure
from hydra.services.certificate_management import CertificateManager
from hydra.services.creator_lock_infrastructure import CreatorFileLock


NAME = "vpn.example.org"


def _pair(domain=NAME, days=90):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=100))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def _lineage(root, name=NAME, days=90):
    live = root / "live" / name
    archive = root / "archive" / name
    live.mkdir(parents=True)
    archive.mkdir(parents=True)
    cert, key = _pair(name, days)
    for filename, data in (("fullchain.pem", cert), ("privkey.pem", key), ("cert.pem", cert), ("chain.pem", cert)):
        (live / filename).write_bytes(data)
    (live / "privkey.pem").chmod(0o600)
    renewal = root / "renewal" / f"{name}.conf"
    renewal.parent.mkdir(exist_ok=True)
    renewal.write_text(
        f"archive_dir = {archive}\ncert = {live / 'cert.pem'}\nprivkey = {live / 'privkey.pem'}\n"
        f"chain = {live / 'chain.pem'}\nfullchain = {live / 'fullchain.pem'}\n"
        "[renewalparams]\nauthenticator = standalone\n",
        encoding="utf8",
    )
    return cert, key


class _Host(HostBackend):
    def __init__(self, root):
        super().__init__()
        self.root, self.calls = root, []
        self.active = {"caddy-l4", "sing-box", "hydra-sub"}
        self.failure = ""
        self.new_pair = None

    def which(self, _executable):
        return "/usr/bin/certbot"

    def run(self, args, **kwargs):
        args = list(args)
        self.calls.append((args, kwargs))
        if args[0] == "systemctl":
            action, unit = args[1:3]
            if action == "is-active":
                return CompletedProcess(
                    args, 0 if unit in self.active else 3, "active" if unit in self.active else "inactive", ""
                )
            if action == "stop":
                self.active.discard(unit)
            else:
                self.active.add(unit)
            if action == "restart" and self.failure in {"restart", "unhealthy"}:
                code = 1 if self.failure == "restart" else 0
                self.failure = ""
                self.active.discard(unit)
                return CompletedProcess(args, code, "", "failed")
        elif args[0] == "certbot":
            if self.failure == "before":
                raise OSError("failure before Certbot side effect")
            name = args[args.index("--cert-name") + 1]
            if args[1] == "renew":
                cert, key = self.new_pair or _pair(name)
                live = self.root / "live" / name
                (live / "fullchain.pem").write_bytes(cert)
                (live / "privkey.pem").write_bytes(key)
            else:
                for path in CertificateFiles(self, self.root).scopes(name):
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink(missing_ok=True)
            if self.failure == "after":
                return CompletedProcess(args, 1, "", "private-plugin-secret")
        elif args[:3] == ["rm", "-rf", "--"]:
            target = Path(args[3])
            assert target.is_relative_to(self.root)
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
        elif args[:3] == ["ln", "-s", "--"]:
            assert Path(args[4]).is_relative_to(self.root / "live")
        elif args[:3] == ["chown", "-h", "--"]:
            assert Path(args[4]).is_relative_to(self.root)
        else:
            pytest.fail(f"Unexpected host command: {args}")
        return CompletedProcess(args, 0, "", "")


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "letsencrypt"
    old = _lineage(root)
    host = _Host(root)
    inspector = MagicMock()
    inspector.inspect.return_value = []
    files = CertificateFiles(host, root)
    runtime = CertificateInfrastructure(host, files, inspector, open_http=nullcontext)
    state = AppState(protocols={"anytls": PluginState(enabled=True, config={"domain": NAME})})
    events = []
    manager = CertificateManager(
        inspector,
        runtime,
        lambda: copy.deepcopy(state),
        CreatorFileLock(host, tmp_path / "apply.lock"),
        lambda event, **fields: events.append((event, fields)),
    )
    return manager, host, state, events, old


def test_inventory_includes_unused_expired_and_external_without_mutation(setup):
    manager, host, state, _, _ = setup
    _lineage(host.root, "unused.example.org", days=-1)
    manager.inspector.inspect.return_value = [
        CertificateStatus("custom", "custom.example", "/custom/cert.pem", "ok", 60)
    ]
    before = copy.deepcopy(state)
    records = manager.inventory()
    assert [item.name for item in records] == ["unused.example.org", NAME, "external:custom"]
    assert records[0].status == "expired"
    assert records[0].used_by == ()
    # Without sub_domain, the subscription server also falls back to this protocol's lineage.
    assert records[1].used_by == ("anytls", "subscriptions")
    assert records[1].days_left > 30
    assert records[2].managed is False
    assert state == before
    assert host.calls == []


def test_force_reissue_reloads_active_services_without_mutating_state(setup):
    manager, host, state, events, old = setup
    before = copy.deepcopy(state)
    result = manager.reissue(NAME)
    assert result.ok
    command = next(args for args, _ in host.calls if args[0] == "certbot")
    assert command[1] == "renew"
    assert "--force-renewal" in command
    assert "--non-interactive" in command
    assert "--no-directory-hooks" in command
    assert command[command.index("--config") + 1] == "/dev/null"
    assert next(options for args, options in host.calls if args[0] == "certbot")["timeout"] == 240
    assert (host.root / "live" / NAME / "fullchain.pem").read_bytes() != old[0]
    assert host.active == {"caddy-l4", "sing-box", "hydra-sub"}
    assert state == before
    assert [event for event, _ in events] == ["certificate_started", "certificate_committed"]


@pytest.mark.parametrize("operation", ["delete", "reissue"])
@pytest.mark.parametrize("failure", ["before", "after"])
def test_failure_before_or_after_effect_restores_lineage_and_running_services(setup, operation, failure):
    manager, host, _, events, old = setup
    host.failure = failure
    result = manager.delete(NAME, confirmation=NAME) if operation == "delete" else manager.reissue(NAME)
    assert not result.ok
    assert result.code == "operation_failed"
    assert (host.root / "live" / NAME / "fullchain.pem").read_bytes() == old[0]
    assert (host.root / "live" / NAME / "privkey.pem").read_bytes() == old[1]
    assert host.active == {"caddy-l4", "sing-box", "hydra-sub"}
    assert events[-1][0] == "certificate_failed"
    assert "private-plugin-secret" not in result.message


@pytest.mark.parametrize("failure", ["restart", "unhealthy"])
def test_failed_service_restart_restores_previous_certificate_first(setup, failure):
    manager, host, _, events, old = setup
    host.failure = failure
    result = manager.reissue(NAME)
    assert not result.ok
    assert (host.root / "live" / NAME / "fullchain.pem").read_bytes() == old[0]
    assert host.active == {"caddy-l4", "sing-box", "hydra-sub"}
    assert events[-1][1]["rollback_failed"] == []


def test_explicit_confirmation_allows_delete_even_if_currently_used(setup):
    manager, host, state, events, _ = setup
    before = copy.deepcopy(state)
    assert manager.delete(NAME, confirmation="wrong").code == "confirmation_required"
    assert host.calls == []
    result = manager.delete(NAME, confirmation=NAME)
    assert result.ok
    assert not any(path.exists() for path in manager.runtime.files.scopes(NAME))
    assert not any(args[0] == "systemctl" for args, _ in host.calls)
    assert state == before  # Intentional: deleting a certificate doesn't disable protocols.
    assert events[-1][0] == "certificate_committed"


@pytest.mark.parametrize(
    "setting", ["pre_hook", "post_hook", "renew_hook", "deploy_hook", "manual_auth_hook", "manual_cleanup_hook"]
)
def test_reissue_never_executes_persisted_shell_hooks(setup, setting):
    manager, host, _, _, _ = setup
    path = host.root / "renewal" / f"{NAME}.conf"
    with path.open("a", encoding="utf8") as output:
        output.write(f"{setting} = echo PRIVATE_PLUGIN_SECRET\n")
    result = manager.reissue(NAME)
    assert not result.ok
    assert "hooks" in result.message
    assert "PRIVATE_PLUGIN_SECRET" not in result.message
    assert not any(args[0] == "certbot" or args[:2] == ["systemctl", "stop"] for args, _ in host.calls)


def test_reissue_rejects_installers_that_mutate_unsnapshotted_server_configuration(setup):
    manager, host, _, _, _ = setup
    path = host.root / "renewal" / f"{NAME}.conf"
    with path.open("a", encoding="utf8") as output:
        output.write("installer = nginx\n")
    assert not manager.reissue(NAME).ok
    assert not any(args[0] == "certbot" for args, _ in host.calls)


def test_delete_with_saved_hooks_is_allowed_but_hooks_and_global_cli_config_are_disabled(setup):
    manager, host, _, _, _ = setup
    path = host.root / "renewal" / f"{NAME}.conf"
    with path.open("a", encoding="utf8") as output:
        output.write("deploy_hook = echo PRIVATE_PLUGIN_SECRET\n")
    assert manager.delete(NAME, confirmation=NAME).ok
    command = next(args for args, _ in host.calls if args[0] == "certbot")
    assert command[1] == "delete"
    assert "--no-directory-hooks" in command
    assert command[command.index("--config") + 1] == "/dev/null"


def test_operation_rejects_busy_apply_lock(setup):
    manager, host, _, _, _ = setup
    lease = manager.lock.try_acquire()
    try:
        assert manager.reissue(NAME).code == "busy"
        assert host.calls == []
    finally:
        lease.release()


@pytest.mark.parametrize("name", ["../outside", "/etc/passwd", "-option", "a/../../b"])
def test_lineage_paths_reject_traversal_and_options(setup, name):
    manager, host, _, _, _ = setup
    with pytest.raises(ValueError):
        manager.runtime.files.snapshot(name)
    assert host.calls == []


def test_corrupted_snapshot_is_rejected_before_any_restore_mutation(setup):
    manager, host, _, _, _ = setup
    files = manager.runtime.files
    snapshot = files.snapshot(NAME)
    altered = replace(snapshot.files[0], content=b"tampered")
    with pytest.raises(ValueError, match="snapshot"):
        files.restore(replace(snapshot, files=(altered, *snapshot.files[1:])))
    assert host.calls == []


def test_wrong_key_from_renewal_is_rolled_back(setup):
    manager, host, _, _, old = setup
    host.new_pair = (_pair()[0], _pair()[1])
    assert not manager.reissue(NAME).ok
    assert (host.root / "live" / NAME / "privkey.pem").read_bytes() == old[1]


def test_restore_failure_is_reported_and_does_not_skip_service_recovery(setup):
    manager, host, _, events, _ = setup
    host.failure = "after"
    with patch.object(CertificateFiles, "restore", side_effect=OSError("restore failed")):
        result = manager.reissue(NAME)
    assert result.code == "rollback_failed"
    assert "Certbot renew" in result.message
    assert events[-1][1]["rollback_failed"] == ["TLS lineage"]
    assert host.active == {"caddy-l4", "sing-box", "hydra-sub"}


@pytest.mark.parametrize("invalid", ["../outside", "/etc/passwd"])
def test_restore_rejects_out_of_scope_manifest_before_removing_anything(setup, invalid):
    manager, host, _, _, _ = setup
    snapshot = manager.runtime.files.snapshot(NAME)
    altered = replace(snapshot.files[0], path=invalid)
    with pytest.raises(ValueError, match="manifest"):
        manager.runtime.files.restore(replace(snapshot, files=(altered, *snapshot.files[1:])))
    assert host.calls == []


def test_restore_rejects_escaping_symlink_before_removing_anything(setup):
    manager, host, _, _, _ = setup
    files = manager.runtime.files
    snapshot = files.snapshot(NAME)
    bad_link = (f"live/{NAME}/escape.pem", "../../../../etc/passwd")
    with pytest.raises(ValueError, match="Symlink"):
        files.restore(replace(snapshot, links=(bad_link,)))
    assert host.calls == []


def test_renewal_config_cannot_redirect_certbot_outside_lineage(setup):
    manager, host, _, _, _ = setup
    path = host.root / "renewal" / f"{NAME}.conf"
    text = path.read_text(encoding="utf8").replace(str(host.root / "live" / NAME / "fullchain.pem"), "/etc/passwd")
    path.write_text(text, encoding="utf8")
    assert not manager.reissue(NAME).ok
    assert host.calls == []


def test_wrong_domain_certificate_is_rolled_back(setup):
    manager, host, _, _, old = setup
    host.new_pair = _pair("other.example.org")
    assert not manager.reissue(NAME).ok
    assert (host.root / "live" / NAME / "fullchain.pem").read_bytes() == old[0]


def test_force_renewal_cannot_succeed_without_a_new_certificate(setup):
    manager, host, _, _, old = setup
    host.new_pair = old
    result = manager.reissue(NAME)
    assert not result.ok
    assert "не изменил" in result.message


def test_journal_failure_before_mutation_does_not_touch_lineage_or_services(setup):
    manager, host, _, _, old = setup
    manager = replace(manager, journal=MagicMock(side_effect=OSError("journal unavailable")))
    result = manager.reissue(NAME)
    assert not result.ok
    assert (host.root / "live" / NAME / "fullchain.pem").read_bytes() == old[0]
    assert all(args[:2] == ["systemctl", "is-active"] for args, _ in host.calls)
    lease = manager.lock.try_acquire()
    assert lease is not None
    lease.release()


def test_same_san_in_old_lineage_does_not_mean_it_is_used(setup):
    manager, host, _, _, old = setup
    alias = NAME + "-0001"
    _lineage(host.root, alias)
    (host.root / "live" / alias / "fullchain.pem").write_bytes(old[0])
    record = next(item for item in manager.inventory() if item.name == alias)
    assert record.domains == (NAME,)
    assert record.used_by == ()


def test_explicit_external_pair_does_not_use_certbot_copy_for_protocol(setup):
    manager, _, state, _, _ = setup
    state.protocols["anytls"].config.update(cert_file="/custom/cert.pem", key_file="/custom/key.pem")
    record = next(item for item in manager.inventory() if item.name == NAME)
    assert "anytls" not in record.used_by
    assert "subscriptions" in record.used_by


def test_certbot_live_symlinks_are_snapshotted_and_recreated_through_host(setup, monkeypatch):
    import os

    manager, host, _, _, old = setup
    live, archive, _ = manager.runtime.files.scopes(NAME)
    targets = {
        live / "fullchain.pem": f"../../archive/{NAME}/fullchain1.pem",
        live / "privkey.pem": f"../../archive/{NAME}/privkey1.pem",
    }
    (archive / "fullchain1.pem").write_bytes(old[0])
    (archive / "privkey1.pem").write_bytes(old[1])
    is_symlink, readlink = Path.is_symlink, os.readlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path in targets or is_symlink(path))
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path, **kwargs: targets[Path(path)] if Path(path) in targets else readlink(path, **kwargs),
    )
    snapshot = manager.runtime.files.snapshot(NAME)
    assert set(snapshot.links) == {(path.relative_to(host.root).as_posix(), target) for path, target in targets.items()}
    assert not any(item.path == f"live/{NAME}/privkey.pem" for item in snapshot.files)
    manager.runtime.files.restore(snapshot)
    assert (archive / "fullchain1.pem").read_bytes() == old[0]
    for path, target in targets.items():
        assert any(args == ["ln", "-s", "--", target, str(path)] for args, _ in host.calls)
    for relative, uid, gid in snapshot.owners:
        assert any(args == ["chown", "-h", "--", f"{uid}:{gid}", str(host.root / relative)] for args, _ in host.calls)


def test_snapshot_owner_validation_precedes_restore_mutations(setup):
    manager, host, _, _, _ = setup
    snapshot = manager.runtime.files.snapshot(NAME)
    relative, _, gid = snapshot.owners[0]
    with pytest.raises(ValueError, match="manifest"):
        manager.runtime.files.restore(replace(snapshot, owners=((relative, -1, gid), *snapshot.owners[1:])))
    assert host.calls == []
