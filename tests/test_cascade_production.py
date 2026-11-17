from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import User
from hydra.services.managed_nodes.cascade_accounting import scoped_samples
from hydra.services.managed_nodes.accounting import apply_traffic_samples, reset_managed_node_traffic
from hydra.services.subscriptions.node_exports import CascadeSubscriptionReader
from hydra.core.runtime_users import ProtectedRuntimeUser, shared_runtime_password
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.services.managed_nodes.cascade_stats import _fields
from tests.cascade_lab import CascadeLab, USER
from tests.cascade_lab import management_transport


@pytest.mark.parametrize("topology", [("base", "exit"), ("entry", "base"), ("entry", "exit")])
@pytest.mark.parametrize("protocols", [("vless",), ("anytls",), ("vless", "anytls")])
def test_production_cascade_publishes_only_first_hop_and_preserves_direct_profiles(tmp_path, topology, protocols):
    lab = CascadeLab(tmp_path, topology=topology, protocols=protocols)
    route = CascadeDefinition("route", "Route", *topology, list(protocols))
    direct_before = {identity: node.material(node.read(), protocols[0], USER) for identity, node in lab.nodes.items()}
    operation = lab.service.save_cascade(route, confirmed=True)
    assert operation.state == "succeeded", operation.error
    base = lab.nodes["base"]
    exported = CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, base.read())
    assert {item.protocol for item in exported} == set(protocols)
    entry, exit = lab.nodes[topology[0]], lab.nodes[topology[1]]
    for profile in exported:
        scope = entry.credentials.load(route.id)
        entry_user = scope.subject(entry.identity, profile.protocol, "entry", USER)
        transit_user = scope.subject(exit.identity, profile.protocol, "transit", USER)
        assert entry_user.uuid in str(profile.singbox) or shared_runtime_password(entry_user) in str(profile.singbox)
        assert transit_user.uuid not in str(profile.singbox) + str(profile.links)
        assert shared_runtime_password(transit_user) not in str(profile.singbox) + str(profile.links)
    for identity, node in lab.nodes.items():
        assert node.material(node.read(), protocols[0], USER) == direct_before[identity]
        assert all(user.uuid == USER.uuid for user in node.read().users)
    assert lab.service.refresh() == []


def test_failed_whole_path_rolls_back_both_scopes_and_does_not_publish(tmp_path):
    lab = CascadeLab(tmp_path, protocols=("vless",), probe=False)
    route = CascadeDefinition("route", "Route", "base", "exit", ["vless"])
    baseline = {name: node.render(node.read()) for name, node in lab.nodes.items()}
    operation = lab.service.save_cascade(route, confirmed=True)
    assert operation.state == "failed", operation.error
    assert lab.nodes["base"].records.read_namespace().cascades == []
    assert CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, lab.nodes["base"].read()) == ()
    for name, node in lab.nodes.items():
        assert node.render(node.read()) == baseline[name]


def test_commit_window_keeps_previous_profiles_until_coordinator_commit(tmp_path, monkeypatch):
    lab = CascadeLab(tmp_path, protocols=("vless",))
    route = CascadeDefinition("route", "Route", "base", "exit", ["vless"])
    records = lab.nodes["base"].records
    original = records.commit_cascade_operation
    def inspect(operation_id, candidate):
        assert CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, lab.nodes["base"].read()) == ()
        return original(operation_id, candidate)
    monkeypatch.setattr(records, "commit_cascade_operation", inspect)
    assert lab.service.save_cascade(route, confirmed=True).state == "succeeded"
    assert CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, lab.nodes["base"].read())


def test_rename_filters_current_users_and_remove_cleans_every_participant(tmp_path):
    lab = CascadeLab(tmp_path)
    route = CascadeDefinition("route", "Route", "base", "exit", ["vless", "anytls"])
    assert lab.service.save_cascade(route, confirmed=True).state == "succeeded"
    base = lab.nodes["base"]
    reader = CascadeSubscriptionReader(lab.publications)
    before = reader.profiles_for_user(USER, base.read())
    seeds = {name: node.credentials.export_transfer(route.id).to_document() for name, node in lab.nodes.items()}
    lab.service.rename_cascade(route.id, "Renamed")
    assert lab.service.refresh() == []
    renamed = reader.profiles_for_user(USER, base.read())
    assert {item.name_key for item in renamed} == {item.name_key for item in before}
    assert all(item.name.startswith("Renamed") for item in renamed)
    assert all(node.credentials.export_transfer(route.id).to_document() == seeds[name] for name, node in lab.nodes.items())
    blocked = replace(USER, blocked=True)
    assert reader.profiles_for_user(blocked, base.read()) == ()
    disabled = replace(USER, disabled_protocols=["vless"])
    assert {item.protocol for item in reader.profiles_for_user(disabled, base.read())} == {"anytls"}
    removed = lab.service.remove_cascade(route.id, confirmed=True)
    assert removed.state == "succeeded", removed.error
    for node in lab.nodes.values():
        assert not node.credentials.exists(route.id)
        assert not node.deployments.render(node.read()).users


def test_no_counter_increase_cannot_publish_even_when_client_reports_success(tmp_path):
    lab = CascadeLab(tmp_path, protocols=("vless",))
    # A direct request or unrelated route's traffic cannot prove this cascade.
    from hydra.contracts.managed_node_observations import CheckResult
    lab.runtime._path_publisher.probe_client.probe_client = lambda *args, **kwargs: CheckResult("connection", "route", "ok")
    result = lab.service.save_cascade(CascadeDefinition("route", "Route", "base", "exit", ["vless"]), confirmed=True)
    assert result.state == "failed" and "scoped exit" in result.error["reason"]


def test_entry_counters_single_count_restart_reset_and_retirement():
    from hydra.core.state_models import AppState
    state = AppState(users=[copy.deepcopy(USER)])
    bindings = {"opaque-entry": (USER.uuid, "route-entry", "cascade_entry"),
                "opaque-transit": (USER.uuid, "route-transit", "transit")}
    for runtime, raw, expected in [("first", 100, 100), ("first", 150, 150), ("second", 20, 170), ("second", 20, 170)]:
        samples = scoped_samples(state, bindings, {"opaque-entry": raw, "opaque-transit": 999999}, runtime)
        apply_traffic_samples(state, "entry", samples)
        assert state.users[0].traffic_used_bytes == expected
    retired = scoped_samples(state, {}, {}, "")
    assert retired[0].used_bytes == 170
    reset_managed_node_traffic(state, state.users[0])
    apply_traffic_samples(state, "entry", scoped_samples(state, bindings, {"opaque-entry": 30}, "second"))
    assert state.users[0].traffic_used_bytes == 0
    apply_traffic_samples(state, "entry", scoped_samples(state, bindings, {"opaque-entry": 40}, "second"))
    assert state.users[0].traffic_used_bytes == 10


def test_shared_anytls_credentials_are_independent_of_host_master_key(tmp_path, monkeypatch):
    from hydra.utils import crypto
    subject = ProtectedRuntimeUser("opaque@example.test", USER.uuid, shared_credentials=True)
    keys = [tmp_path / "first.key", tmp_path / "second.key"]
    values, ordinary = [], []
    for index, key in enumerate(keys):
        key.write_bytes(bytes([index + 1]) * 32)
        monkeypatch.setattr(crypto, "MASTER_KEY_FILE", key)
        values.append(AnyTLSPlugin._password_for_user(subject))
        ordinary.append(AnyTLSPlugin._password_for_user(USER))
    assert values[0] == values[1] == shared_runtime_password(subject)
    assert ordinary[0] != ordinary[1]


@pytest.mark.parametrize("raw", [b"\x00", b"\x0a\x10short", b"\x0f", b"\x08\xff"])
def test_stats_decoder_rejects_malformed_messages(raw):
    with pytest.raises(ValueError):
        list(_fields(raw))


@pytest.mark.parametrize("topology", [("base", "exit"), ("entry", "base"), ("entry", "exit")])
def test_production_management_endpoints_use_real_pinned_mtls(tmp_path, topology):
    lab = CascadeLab(tmp_path, topology=topology)
    route = CascadeDefinition("route", "Route", *topology, ["vless", "anytls"])
    with management_transport(lab):
        result = lab.service.save_cascade(route, confirmed=True)
        assert result.state == "succeeded", result.error
        assert lab.service.refresh() == []
        removed = lab.service.remove_cascade(route.id, confirmed=True)
        assert removed.state == "succeeded", removed.error


def test_crash_after_config_effect_recovers_receipt_without_reapplying(tmp_path, monkeypatch):
    lab = CascadeLab(tmp_path, protocols=("vless",))
    node = lab.nodes["exit"]
    update = node.transactions.update
    injected = []
    def interrupt(request, *, phase, **changes):
        if phase == "applied" and not injected:
            injected.append(True)
            raise OSError("receipt write interrupted after config apply")
        return update(request, phase=phase, **changes)
    monkeypatch.setattr(node.transactions, "update", interrupt)
    result = lab.service.save_cascade(CascadeDefinition("route", "Route", "base", "exit", ["vless"]), confirmed=True)
    assert result.state == "succeeded", result.error
    assert node.applies == 1


def test_policy_mismatch_rolls_back_and_never_publishes_a_foreign_user(tmp_path):
    lab = CascadeLab(tmp_path, protocols=("vless",))
    lab.nodes["exit"].state.users.append(User("other@example.test", "other-user"))
    lab.nodes["exit"].write_config()
    result = lab.service.save_cascade(CascadeDefinition("route", "Route", "base", "exit", ["vless"]), confirmed=True)
    assert result.state == "failed", result.error
    assert "user policies" in result.error["reason"]


def test_expiry_block_new_user_and_normal_sync_rebuild_scoped_users(tmp_path):
    lab = CascadeLab(tmp_path, protocols=("vless",))
    route = CascadeDefinition("route", "Route", "base", "exit", ["vless"])
    assert lab.service.save_cascade(route, confirmed=True).state == "succeeded"
    new = User("new@example.test", "bf3e675e-bccd-42c9-9b4d-f74515a492e5")
    for node in lab.nodes.values():
        node.state.users = [replace(USER, blocked=True), copy.deepcopy(new)]
        node.write_config()
        contributed = node.deployments.render(node.read())
        scope = node.credentials.load(route.id)
        role = "entry" if node.identity == route.entry_id else "transit"
        old_subject = scope.subject(node.identity, "vless", role, USER)
        assert old_subject.email not in [item.email for item in contributed.users]
        assert scope.subject(node.identity, "vless", role, new).email in [item.email for item in contributed.users]
    assert lab.service.refresh() == []
    reader = CascadeSubscriptionReader(lab.publications)
    assert reader.profiles_for_user(new, lab.nodes["base"].read())
    assert reader.profiles_for_user(replace(USER, blocked=True), lab.nodes["base"].read()) == ()
