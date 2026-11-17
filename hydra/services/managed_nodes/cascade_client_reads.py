"""Bounded authenticated reads for cascade capabilities, proof and publication."""
from __future__ import annotations

from hydra.contracts.managed_node_cascade import CascadeParticipantReceipt
from hydra.contracts.managed_node_models import canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfile
from hydra.contracts.managed_node_probe import ProbeMaterial


class CascadeClientReads:
    def cascade_capabilities(self, deadline):
        def decode(raw):
            if not isinstance(raw, dict) or set(raw) != {"participant_id", "engine_identity", "protocols"}:
                raise ValueError("invalid cascade capability response")
            if raw["participant_id"] != self.node_id:
                raise ValueError("foreign cascade capability response")
            if not _digest(raw["engine_identity"]):
                raise ValueError("invalid cascade engine identity")
            protocols = raw["protocols"]
            if not isinstance(protocols, dict) or set(protocols) != {"vless", "anytls"}:
                raise ValueError("invalid cascade protocol capability response")
            for value in protocols.values():
                if not isinstance(value, dict) or set(value) != {"client", "server", "probe"} or any(type(v) is not bool for v in value.values()):
                    raise ValueError("invalid cascade capability evidence")
            return raw
        return self._request("POST", "/v1/cascades/capabilities", {}, deadline, decode)

    def cascade_probe_state(self, request, deadline):
        return self._request("POST", "/v1/cascades/probe-state", {"request": request.to_document()}, deadline,
                             lambda raw: validate_evidence(raw, request))

    def cascade_publication(self, request, deadline):
        def decode(raw):
            validate_evidence(raw, request, publication=True)
            ProbeMaterial(request.protocol, raw["probe_endpoint"]).validate()
            for document in raw["profiles"]:
                profile = ConfirmedProfile.from_document(document)
                if profile.protocol != request.protocol or profile.route_id != request.target_id:
                    raise ValueError("foreign cascade publication profile")
            if len({item["stable_id"] for item in raw["profiles"]}) != len(raw["profiles"]):
                raise ValueError("duplicate cascade profile identity")
            return raw
        return self._request("POST", "/v1/cascades/publication", {"request": request.to_document()}, deadline, decode)


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate_evidence(raw, request, *, publication=False):
    keys = {"receipt", "runtime_id", "counter", "policy_digest"}
    if publication:
        keys |= {"profiles", "probe_endpoint"}
    if not isinstance(raw, dict) or set(raw) != keys:
        raise ValueError("invalid cascade live evidence")
    receipt = CascadeParticipantReceipt.from_document(raw["receipt"])
    receipt.validate_for(request)
    if receipt.state != "applied" or not _digest(raw["runtime_id"]) or not _digest(raw["policy_digest"]):
        raise ValueError("unconfirmed cascade context evidence")
    if type(raw["counter"]) is not int or raw["counter"] < 0:
        raise ValueError("invalid cascade cumulative counter")
    if publication and not isinstance(raw["profiles"], list):
        raise ValueError("invalid cascade profile collection")
    return raw
