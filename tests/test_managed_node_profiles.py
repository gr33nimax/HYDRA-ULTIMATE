from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from hydra.contracts.managed_node_models import ApplyReceipt, canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfile, ConfirmedProfiles
from hydra.core.host import HOST
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.profiles import ManagedNodeProfileBuilder


def _symlink_factory(monkeypatch):
    simulated: set[Path] = set()
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path in simulated or real_is_symlink(path))

    def create(link: Path, target: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
                raise
            simulated.add(link)

    return create, simulated


def bundle(operation_id: str, runtime_id: str, profile: ConfirmedProfile) -> ConfirmedProfiles:
    profiles = [profile]
    digest = canonical_digest([item.to_document() for item in profiles])
    receipt = ApplyReceipt(operation_id, 1, "a" * 64, runtime_id, "b" * 64, digest)
    return ConfirmedProfiles("de-1", receipt, profiles, digest)


def test_same_profile_content_can_be_committed_for_a_new_receipt(tmp_path: Path):
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    profile = ConfirmedProfile("p1", "user-1", "vless", "direct")
    first = bundle("apply-1", "runtime-1", profile)
    second = bundle("apply-2", "runtime-2", profile)

    store.commit(first, expected_users={"user-1"})
    # Public profiles_digest is unchanged; storage identity must include the receipt.
    store.commit(second, expected_users={"user-1"})

    assert first.sha256 == second.sha256
    assert store.read("de-1", receipt_is_committed=lambda item: item.receipt == second.receipt) == second


def test_same_receipt_retry_is_idempotent_and_uncommitted_current_falls_back(tmp_path: Path):
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    old = bundle("apply-old", "runtime-old", ConfirmedProfile("p1", "user-1", "vless", "direct"))
    current = bundle("apply-new", "runtime-new", ConfirmedProfile("p2", "user-1", "vless", "mobile"))
    store.commit(old, expected_users={"user-1"})
    store.commit(old, expected_users={"user-1"})
    store.commit(current, expected_users={"user-1"})

    selected = store.read("de-1", receipt_is_committed=lambda item: item.receipt == old.receipt)
    assert selected == old


def test_confirmed_profile_rejects_newline_injection_and_relative_links():
    for link in ("vless://payload\nvless://injected", "not-a-link"):
        with pytest.raises(ValueError, match="profile.links"):
            ConfirmedProfile("p1", "user-1", "vless", "direct", links=[link]).validate()
    with pytest.raises(ValueError, match="profile.route_id"):
        ConfirmedProfile("p1", "user-1", "vless", "bad\\nprofile").validate()


def test_profile_commit_rejects_unexpected_users_and_duplicate_profile_ids(tmp_path: Path):
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    foreign = bundle("apply-foreign", "runtime-foreign", ConfirmedProfile("p1", "user-2", "vless", "direct"))
    with pytest.raises(ValueError, match="do not cover"):
        store.commit(foreign, expected_users={"user-1"})

    profile = ConfirmedProfile("p1", "user-1", "vless", "direct")
    profiles = [profile, profile]
    profiles_digest = canonical_digest([item.to_document() for item in profiles])
    receipt = ApplyReceipt("apply-duplicate", 1, "a" * 64, "runtime-duplicate", "b" * 64, profiles_digest)
    duplicate = ConfirmedProfiles("de-1", receipt, profiles, profiles_digest)
    with pytest.raises(ValueError, match="duplicate identifiers"):
        duplicate.validate()


def test_profile_builder_skips_user_disabled_transport():
    transport = SimpleNamespace(meta=SimpleNamespace(capabilities=SimpleNamespace(subscription_enabled=True)))
    protocols = SimpleNamespace(get=lambda _name: transport)
    state = AppState(
        users=[User("one@example.test", "user-1", disabled_protocols=["vless"])],
        protocols={"vless": PluginState(enabled=True)},
    )

    assert ManagedNodeProfileBuilder(protocols=protocols).build(state, "de-1") == []


def test_profile_read_rejects_symlinked_root_and_node_directories(tmp_path: Path, monkeypatch):
    create_symlink, _simulated = _symlink_factory(monkeypatch)
    external = tmp_path / "external"
    external.mkdir()
    linked_root = tmp_path / "profiles-link"
    create_symlink(linked_root, external, directory=True)
    linked_store = ManagedNodeProfileStore(host=HOST, root=linked_root)
    with pytest.raises(ValueError, match="unsafe"):
        linked_store.read("de-1")
    assert list(external.iterdir()) == []

    root = tmp_path / "profiles"
    root.mkdir()
    linked_node = root / "de-1"
    create_symlink(linked_node, external, directory=True)
    store = ManagedNodeProfileStore(host=HOST, root=root)
    with pytest.raises(ValueError, match="unsafe"):
        store.read("de-1")
    assert list(external.iterdir()) == []


def test_profile_read_rejects_symlinked_pointer_and_bundle(tmp_path: Path, monkeypatch):
    create_symlink, simulated = _symlink_factory(monkeypatch)
    root = tmp_path / "profiles"
    node_dir = root / "de-1"
    node_dir.mkdir(parents=True)
    pointer_target = tmp_path / "pointer.json"
    pointer_target.write_text('{"version":1,"current":null,"previous":null}', encoding="utf-8")
    create_symlink(node_dir / "current.json", pointer_target)
    store = ManagedNodeProfileStore(host=HOST, root=root)
    with pytest.raises(ValueError, match="unsafe"):
        store.read("de-1")

    pointer_path = node_dir / "current.json"
    pointer_path.unlink(missing_ok=True)
    simulated.discard(pointer_path)
    expected = bundle("apply-1", "runtime-1", ConfirmedProfile("p1", "user-1", "vless", "direct"))
    store.commit(expected, expected_users={"user-1"})
    pointer = json.loads((node_dir / "current.json").read_text(encoding="utf-8"))
    bundle_path = node_dir / f"{pointer['current']}.json"
    bundle_payload = bundle_path.read_bytes()
    bundle_path.unlink()
    bundle_target = tmp_path / "bundle.json"
    bundle_target.write_bytes(bundle_payload)
    create_symlink(bundle_path, bundle_target)
    with pytest.raises(ValueError, match="unsafe"):
        store.read("de-1")


def test_profile_bundle_tampering_and_oversize_are_rejected(tmp_path: Path):
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    item = bundle("apply-1", "runtime-1", ConfirmedProfile("p1", "user-1", "vless", "direct"))
    store.commit(item, expected_users={"user-1"})
    pointer = json.loads((tmp_path / "profiles" / "de-1" / "current.json").read_text(encoding="utf-8"))
    path = tmp_path / "profiles" / "de-1" / f"{pointer['current']}.json"
    path.write_bytes(path.read_bytes() + b"tampered")
    assert store.read("de-1") is None
    with pytest.raises(ValueError, match="digest collision"):
        store.commit(item, expected_users={"user-1"})

    huge_profile = ConfirmedProfile(
        "large", "user-1", "vless", "direct", client_configs=[{"payload": "x" * (2 * 1024 * 1024)}]
    )
    with pytest.raises(ValueError, match="size limit"):
        store.commit(bundle("apply-large", "runtime-large", huge_profile), expected_users={"user-1"})


def test_profile_read_is_read_only_for_missing_store(tmp_path: Path):
    root = tmp_path / "profiles"
    store = ManagedNodeProfileStore(host=HOST, root=root)
    assert store.read("de-1") is None
    assert not root.exists()


def test_profile_store_does_not_publish_a_bundle_with_missing_business_users(tmp_path: Path):
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    empty = ConfirmedProfiles(
        "de-1",
        ApplyReceipt("apply-1", 1, "a" * 64, "runtime-1", "b" * 64, canonical_digest([])),
        [],
        canonical_digest([]),
    )
    with pytest.raises(ValueError, match="cover"):
        store.commit(empty, expected_users={"business-user"})
