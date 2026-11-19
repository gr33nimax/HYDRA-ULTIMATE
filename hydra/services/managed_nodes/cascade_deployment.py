"""Receipt-bound participant overlays built with scoped canonical client templates."""
from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

from hydra.contracts import ConfigFragment, RuntimeRenderContributions, RuntimeSubject
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import canonical_digest
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import User
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.cascade_storage import CascadeArtifacts
from hydra.services.user_access import access_status
from hydra.core.runtime_users import shared_runtime_password


def credential_outbound(template: dict, protocol: str, subject: User) -> dict:
    outbound = copy.deepcopy(template)
    outbound["uuid" if protocol == "vless" else "password"] = (
        subject.uuid if protocol == "vless" else shared_runtime_password(subject)
    )
    ProbeMaterial(protocol, outbound).validate()
    return outbound


def _append(fragment, request, subject, template):
    if request.role == "transit":
        fragment.route_rules.append({"auth_user": [subject.email], "outbound": "direct"})
        return
    outbound = copy.deepcopy(template)
    ProbeMaterial(request.protocol, outbound).validate()
    tag = f"cascade-{request.target_id}-{request.protocol}-" + hashlib.sha256(subject.uuid.encode()).hexdigest()[:12]
    outbound["tag"] = tag
    fragment.outbounds.append(outbound)
    fragment.route_rules.extend([{"auth_user": [subject.email], "outbound": tag},
                                 {"auth_user": [subject.email], "action": "reject"}])


class CascadeDeploymentStore:
    def __init__(self, *, host, root, participant_id, credentials, transactions):
        self.artifacts = CascadeArtifacts(host, root)
        self.participant_id, self.credentials, self.transactions = participant_id, credentials, transactions

    @staticmethod
    def key(request):
        return f"stage-{request.operation_id}-{request.protocol}"

    @staticmethod
    def active_key(request):
        return f"active-{request.target_id}-{request.protocol}"

    def stage(self, request, peer, endpoint):
        request.validate()
        if request.participant_id != self.participant_id:
            raise ValueError("foreign cascade deployment")
        ProbeMaterial(request.protocol, endpoint).validate()
        if request.role == "entry":
            ProbeMaterial(request.protocol, peer).validate()
        elif peer is not None:
            raise ValueError("transit deployment must not contain peer material")
        document = {"request": request.to_document(), "peer": peer, "endpoint": endpoint}
        prior = self.artifacts.read(self.key(request))
        if prior is not None and prior != document:
            raise ValueError("cascade deployment retry changed immutable material")
        if prior is None:
            self.artifacts.write(self.key(request), document)
        return document

    def document(self, request):
        document = self.artifacts.read(self.key(request))
        if document is None or document["request"] != request.to_document():
            raise ValueError("cascade deployment does not match the operation")
        return document

    def finalize(self, request):
        if request.kind == "cascade_remove":
            self.artifacts.remove(self.active_key(request))
            for key, document in list(self.artifacts.items()):
                if not key.startswith("stage-"):
                    continue
                previous = self._request(document)
                if previous.target_id == request.target_id and previous.protocol == request.protocol:
                    self.discard(previous)
        else:
            self.artifacts.write(self.active_key(request), self.document(request))

    def discard(self, request):
        self.artifacts.remove(self.key(request))
        self.artifacts.remove("effect-" + request.operation_id + "-" + request.protocol)

    def selected(self, state):
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operations = {item.id: item for item in namespace.operations}
        routes = {item.id: item for item in namespace.cascades}
        selected = {}
        documents = list(self.artifacts.items())
        for key, document in documents:
            if not key.startswith("active-"):
                continue
            request = self._request(document)
            route = routes.get(request.target_id)
            if route is not None and replace(route, name=request.route.name) == request.route:
                selected[(request.target_id, request.protocol)] = document
        for key, document in documents:
            if not key.startswith("stage-"):
                continue
            request = self._request(document)
            operation = operations.get(request.operation_id)
            record = self.transactions.record(request)
            if operation is None or operation.plan != request.plan or record is None:
                continue
            if record["phase"] in {"prepared", "applying", "applied"} and not record["rollback_requested"]:
                if operation.state in {"pending", "running", "recovery_required", "succeeded"}:
                    selected[(request.target_id, request.protocol)] = document
        return tuple(selected.values())

    def _request(self, document):
        if not isinstance(document, dict) or set(document) != {"request", "peer", "endpoint"}:
            raise ValueError("invalid cascade deployment artifact")
        request = CascadeParticipantRequest.from_document(document["request"])
        if request.participant_id != self.participant_id:
            raise ValueError("foreign cascade deployment artifact")
        ProbeMaterial(request.protocol, document["endpoint"]).validate()
        if request.role == "entry":
            ProbeMaterial(request.protocol, document["peer"]).validate()
        return request

    def render(self, state):
        excluded = {(item.cascade_id, item.protocol): item for item in self.transactions.restoration_contexts(state)}
        users, fragment = [], ConfigFragment()
        for document in self.selected(state):
            request = self._request(document)
            restoring = excluded.get((request.target_id, request.protocol))
            if restoring is not None:
                restoring_request = self.transactions.request_for(restoring.operation_id, self.participant_id, request.protocol)
                record = self.transactions.record(restoring_request) if restoring_request is not None else None
                if not record or not record["rollback_requested"]:
                    continue
            desired = state.protocols.get(request.protocol)
            if desired is None or not desired.enabled:
                continue
            scope = self.credentials.load(request.target_id)
            for business in state.users:
                if restoring is not None:
                    continue
                if not access_status(business)[0] or request.protocol in business.disabled_protocols:
                    continue
                local = scope.subject(self.participant_id, request.protocol, request.role, business)
                users.append(RuntimeSubject(local.email, local.uuid, (request.protocol,), True))
                transit = scope.subject(request.route.exit_id, request.protocol, "transit", business)
                _append(fragment, request, local, credential_outbound(document["peer"], request.protocol, transit)
                        if request.role == "entry" else None)
            # Probe credentials are scoped separately and never published as business identities.
            technical = scope.technical_subject(self.participant_id, request.protocol, request.role, request.operation_id)
            users.append(RuntimeSubject(technical.email, technical.uuid, (request.protocol,), True))
            peer = scope.technical_subject(request.route.exit_id, request.protocol, "transit", request.operation_id)
            template = credential_outbound(document["peer"], request.protocol, peer) if request.role == "entry" else None
            _append(fragment, request, technical, template)
        return RuntimeRenderContributions(tuple(users), {"deployed_cascades": fragment} if users else {})

    def capture(self, state, request, previous):
        if previous is None:
            return CascadeRestoreContext.empty(request)
        document = next((item for item in self.selected(state)
                         if self._request(item).target_id == request.target_id
                         and self._request(item).protocol == request.protocol), None)
        if document is None:
            return CascadeRestoreContext.empty(request)
        scope = self.credentials.load(request.target_id)
        previous_request = self._request(document)
        users, business_ids, fragment = [], [], ConfigFragment()
        for business in state.users:
            if not access_status(business)[0] or request.protocol in business.disabled_protocols:
                continue
            local = scope.subject(self.participant_id, request.protocol, previous_request.role, business)
            users.append(RuntimeSubject(local.email, local.uuid, (request.protocol,), True))
            business_ids.append(business.uuid)
            transit = scope.subject(previous.exit_id, request.protocol, "transit", business)
            template = credential_outbound(document["peer"], request.protocol, transit) if previous_request.role == "entry" else None
            _append(fragment, previous_request, local, template)
        return CascadeRestoreContext(request.target_id, previous.entry_id, previous.exit_id, request.operation_id,
                                     request.plan_digest, self.participant_id, request.protocol,
                                     tuple(business_ids), tuple(users), fragment)

    def counter_bindings(self, state):
        bindings = {}
        for document in self.selected(state):
            request = self._request(document)
            scope = self.credentials.load(request.target_id)
            for business in state.users:
                subject = scope.subject(self.participant_id, request.protocol, request.role, business)
                context = "cascade-" + canonical_digest({"id": request.target_id, "protocol": request.protocol})[:40]
                bindings[subject.email] = (business.uuid, context, "cascade_entry" if request.role == "entry" else "transit")
        return bindings
