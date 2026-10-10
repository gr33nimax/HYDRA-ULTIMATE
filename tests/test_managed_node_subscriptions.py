from __future__ import annotations

from pathlib import Path

from hydra.contracts.managed_node_models import ApplyReceipt, NodeDefinition, Operation, canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfile, ConfirmedProfiles
from hydra.core import state as state_backend
from hydra.core.host import HOST
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.subscriptions.node_exports import ManagedNodeSubscriptionReader


def test_subscription_reads_only_committed_business_profiles_from_protected_store(tmp_path: Path):
    state_backend.save_state(AppState(users=[User("one@example.test", "user-1")]))
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    definition = NodeDefinition(
        "de-1", "Germany", "203.0.113.4", "root", "dev", "a" * 40, 24443,
        [], "managed-node/de-1",
    )
    records.put_definition(definition)
    profile = ConfirmedProfile(
        "business-profile", "user-1", "vless", "direct",
        links=["vless://business@203.0.113.4:443"],
        client_configs=[{"outbounds": [{"type": "vless", "uuid": "business-secret"}]}],
    )
    digest = canonical_digest([profile.to_document()])
    receipt = ApplyReceipt("apply-1", 1, "b" * 64, "runtime-1", "c" * 64, digest)
    bundle = ConfirmedProfiles("de-1", receipt, [profile], digest)
    records.begin_operation(Operation("apply-1", "apply", "de-1", receipt.desired_digest, "succeeded", receipt=receipt))
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    store.commit(bundle, expected_users={"user-1"})

    reader = ManagedNodeSubscriptionReader(profile_store=store)
    current = state_backend.load_state()
    exported = reader.profiles_for_user(current.users[0], current)
    outsider = reader.profiles_for_user(User("two@example.test", "user-2"), current)

    assert len(exported) == 1
    assert exported[0].node_id == "de-1"
    assert exported[0].links == ("vless://business@203.0.113.4:443#%F0%9F%8C%90%20Germany%20%C2%B7%20vless",)
    assert outsider == ()


def test_uncommitted_or_unconfirmed_profile_bundle_is_never_exported(tmp_path: Path):
    state_backend.save_state(AppState(users=[User("one@example.test", "user-1")]))
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    records.put_definition(NodeDefinition("de-1", "Germany", "203.0.113.4", "root", "dev", "a" * 40, 24443, [], "managed-node/de-1"))
    profile = ConfirmedProfile("p1", "user-1", "vless", "direct", links=["vless://one@203.0.113.4:443"])
    digest = canonical_digest([profile.to_document()])
    receipt = ApplyReceipt("apply-uncommitted", 1, "b" * 64, "runtime-1", "c" * 64, digest)
    bundle = ConfirmedProfiles("de-1", receipt, [profile], digest)
    store = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    store.commit(bundle, expected_users={"user-1"})

    current = state_backend.load_state()
    assert ManagedNodeSubscriptionReader(profile_store=store).profiles_for_user(current.users[0], current) == ()
