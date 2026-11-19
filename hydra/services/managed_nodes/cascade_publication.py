"""Whole-path proof and route-only protected publication with commit-gated fallback."""
from __future__ import annotations

from dataclasses import replace

from hydra.contracts.managed_node_cascade import CascadeParticipantRequest, CascadeParticipantReceipt
from hydra.contracts.managed_node_models import CascadeDefinition, canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfile
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.services.managed_nodes.cascade_client_reads import validate_evidence
from hydra.services.managed_nodes.cascade_production_participant import policy_digest
from hydra.services.managed_nodes.cascade_storage import CascadeArtifacts
from hydra.services.managed_nodes.profiles import expected_profile_pairs
from hydra.contracts.managed_node_models import ProtocolAssignment


class CascadePublicationStore:
    def __init__(self, *, host, root):
        self.artifacts = CascadeArtifacts(host, root)

    def save_proof(self, operation_id, document):
        self.artifacts.write("proof-" + operation_id, document)

    def commit(self, operation, route):
        document = self.artifacts.read("proof-" + operation.id) if route is not None else {"protocols": []}
        if document is None:
            raise ValueError("cascade publication has no whole-path proof")
        bundle = {"operation_id": operation.id, "plan_digest": operation.desired_digest,
                  "route": route.to_document() if route is not None else None, **document}
        self.artifacts.write("bundle-" + operation.id, bundle)
        key = "pointer-" + operation.target_id
        previous = self.artifacts.read(key)
        current = operation.id
        fallback = previous.get("current") if previous else None
        if fallback == current:
            fallback = previous.get("previous")
        self.artifacts.write(key, {"current": current, "previous": fallback, "available": True})

    def suspend(self, route_id):
        key = "pointer-" + route_id
        pointer = self.artifacts.read(key)
        if pointer is not None:
            self.artifacts.write(key, {**pointer, "available": False})

    def read(self, state, route):
        pointer = self.artifacts.read("pointer-" + route.id)
        if pointer is None or pointer.get("available") is not True:
            return None
        operations = {item.id: item for item in managed_nodes_from_extensions(state.feature_extensions).operations}
        for key in (pointer.get("current"), pointer.get("previous")):
            if key is None:
                continue
            document = self.artifacts.read("bundle-" + key)
            operation = operations.get(key)
            if document is None or operation is None or operation.kind != "cascade_save" or operation.state != "succeeded":
                continue
            if document["plan_digest"] != operation.desired_digest or document["route"] != operation.plan["cascade"]:
                continue
            candidate = CascadeDefinition.from_document(document["route"])
            if replace(route, name=candidate.name) != candidate:
                continue
            self._validate(document, operation, candidate)
            return document
        return None

    def _validate(self, document, operation, route):
        if {item["protocol"] for item in document["protocols"]} != set(route.protocols):
            raise ValueError("incomplete cascade protocol proof")
        for item in document["protocols"]:
            protocol = item["protocol"]
            for role, participant in (("entry", route.entry_id), ("transit", route.exit_id)):
                request = CascadeParticipantRequest(operation.id, operation.kind, route.id, operation.desired_digest,
                                                    operation.plan, participant, role, candidate_route(operation), protocol)
                receipt = CascadeParticipantReceipt.from_document(item[role + "_receipt"])
                receipt.validate_for(request)
                if receipt.state != "applied":
                    raise ValueError("unconfirmed cascade publication")
            if item["counter_after"] <= item["counter_before"] or item["runtime_before"] != item["runtime_after"]:
                raise ValueError("cascade publication has no matching transit-path counter proof")
            for profile in item["profiles"]:
                parsed = ConfirmedProfile.from_document(profile)
                if parsed.protocol != protocol or parsed.route_id != route.id:
                    raise ValueError("cascade profile is bound to another route")


def candidate_route(operation):
    return CascadeDefinition.from_document(operation.plan["cascade"])


class CascadePathPublisher:
    def __init__(self, *, records, state_reader, invoke, request, probe_client, store):
        self.records, self.state_reader, self.invoke, self.request = records, state_reader, invoke, request
        self.probe_client, self.store = probe_client, store

    def verify(self, operation, route, deadline):
        frozen = candidate_route(operation)
        if replace(route, name=frozen.name) != frozen:
            raise ValueError("cascade verification differs from its committed topology")
        route = frozen
        expected_policy = policy_digest(self.state_reader())
        protocols = []
        for protocol in route.protocols:
            entry = self.request(operation, route.entry_id, route, protocol)
            exit = self.request(operation, route.exit_id, route, protocol)
            before = validate_evidence(self.invoke("probe_state", exit, deadline), exit)
            publication = validate_evidence(self.invoke("publication", entry, deadline), entry, publication=True)
            if before["policy_digest"] != expected_policy or publication["policy_digest"] != expected_policy:
                raise ValueError("cascade participant user policies differ from the base")
            material = ProbeMaterial(protocol, publication["probe_endpoint"])
            material.validate()
            result = self.probe_client.probe_client(material, node_id=route.id, deadline=deadline)
            if result.outcome != "ok":
                raise RuntimeError("whole-path client verification failed: " + result.reason)
            after = validate_evidence(self.invoke("probe_state", exit, deadline), exit)
            if before["runtime_id"] != after["runtime_id"] or before["receipt"] != after["receipt"]:
                raise RuntimeError("exit runtime changed during the cascade probe")
            if after["counter"] <= before["counter"]:
                raise RuntimeError("probe did not traverse the scoped exit context")
            profiles = [ConfirmedProfile.from_document(item) for item in publication["profiles"]]
            actual_pairs = {(item.user_uuid, item.protocol) for item in profiles}
            expected_pairs = expected_profile_pairs(self.state_reader().users, [ProtocolAssignment(protocol)])
            if actual_pairs != expected_pairs:
                raise ValueError("cascade profiles do not cover current entitled users")
            protocols.append({"protocol": protocol, "entry_receipt": publication["receipt"],
                              "transit_receipt": after["receipt"], "runtime_before": before["runtime_id"],
                              "runtime_after": after["runtime_id"], "counter_before": before["counter"],
                              "counter_after": after["counter"], "profiles": publication["profiles"]})
        if policy_digest(self.state_reader()) != expected_policy:
            raise ValueError("base user policy changed during cascade verification")
        self.store.save_proof(operation.id, {"policy_digest": expected_policy, "protocols": protocols})
        return True
