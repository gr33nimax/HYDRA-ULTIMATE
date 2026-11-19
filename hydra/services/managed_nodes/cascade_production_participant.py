"""Production participant activation, authenticated material and live path evidence."""
from __future__ import annotations

from dataclasses import replace

from hydra.contracts.managed_node_models import canonical_digest
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_managed_nodes import managed_nodes_from_extensions, store_managed_nodes
from hydra.services.managed_nodes.access import assignment_from_user
from hydra.services.managed_nodes.accounting import traffic_reset_epoch
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant
from hydra.services.managed_nodes.cascade_participant_removal import prepare_removal
from hydra.services.managed_nodes.cascade_stats import user_counters
from hydra.services.managed_nodes.cascade_deployment import credential_outbound
from hydra.services.managed_nodes.profiles import ManagedNodeProfileBuilder
from hydra.services.user_access import access_status


def policy_digest(state):
    return canonical_digest([assignment_from_user(user, reset_epoch=traffic_reset_epoch(state, user)).to_document()
                             for user in sorted(state.users, key=lambda item: item.uuid)])


class ProductionCascadeParticipant(ManagedNodeCascadeParticipant):
    def __init__(self, *, deployments, preview, observe, capability_probe, final_accounting, protocols,
                 finalize_state, stats_reader=user_counters, **kwargs):
        super().__init__(**kwargs)
        self.deployments, self.preview, self.observe = deployments, preview, observe
        self.capability_probe, self.final_accounting = capability_probe, final_accounting
        self.protocols, self.finalize_state, self.stats_reader = protocols, finalize_state, stats_reader

    def capabilities(self):
        engine, _config = self._context()
        state = self._state_reader()
        protocols = {}
        for name in ("vless", "anytls"):
            enabled = state.protocols.get(name)
            proven = bool(enabled and enabled.enabled and self.capability_probe(name, engine))
            protocols[name] = {"client": proven, "server": proven, "probe": proven}
        return {"participant_id": self.participant_id, "engine_identity": engine, "protocols": protocols}

    def _prepare_owned(self, request, transfer, material):
        self._require_operation(request)
        record = self._require_record(request)
        if record["phase"] in {"prepared", "applying", "applied"}:
            self._credentials.validate_transfer(transfer)
            expected = material.outbound if material is not None else None
            if self.deployments.document(request)["peer"] != expected:
                raise ValueError("cascade retry changed transit material")
            from hydra.contracts.managed_node_cascade import CascadeParticipantReceipt
            return CascadeParticipantReceipt.from_document(record["preparation_receipt"])
        if record["phase"] != "snapshotted":
            raise ValueError("cascade preparation requires an intact snapshot")
        scope = self._credentials.import_transfer(transfer)
        subject = scope.technical_subject(self.participant_id, request.protocol, request.role, request.operation_id)
        endpoint = self._client_material(self._state_reader(), request.protocol, subject)
        ProbeMaterial(request.protocol, endpoint).validate()
        if credential_outbound(endpoint, request.protocol, subject) != endpoint:
            raise ValueError("cascade endpoint credential differs from its scoped identity")
        peer = material.outbound if material is not None else None
        if peer is not None:
            transit = scope.technical_subject(request.route.exit_id, request.protocol, "transit", request.operation_id)
            if credential_outbound(peer, request.protocol, transit) != peer:
                raise ValueError("cascade transit credential differs from its scoped identity")
        self.deployments.stage(request, peer, endpoint)
        engine, config = self._context()
        digest = canonical_digest(endpoint) if request.role == "transit" else None
        receipt = self._receipt(request, "prepared", engine, config, digest)
        self._store.update(request, phase="prepared", receipt=receipt.to_document(),
                           preparation_receipt=receipt.to_document(),
                           material={"outbound": endpoint} if request.role == "transit" else material.to_document())
        return receipt

    def _apply_owned(self, request):
        self._require_operation(request)
        record = self._require_record(request)
        if record["phase"] == "applied":
            return self._current_applied_receipt(request, record)
        if request.kind == "cascade_remove" and record["phase"] in {"snapshotted", "prepared"}:
            # Account before the context is removed or the process counter is reset.
            record = prepare_removal(request, store=self._store, gate=self._gate, state_reader=self._state_reader,
                                     context_reader=self._context, capture_target=self._capture_remove_config_identity)
        if record["phase"] != "prepared":
            raise ValueError("cascade apply result is not safely replayable")
        engine, config_before = self._context()
        if engine != record["receipt"]["engine_identity"]:
            raise ValueError("cascade engine changed after preparation")
        target = self.preview(self._state_reader())
        self.final_accounting()
        evidence_key = "effect-" + request.operation_id + "-" + request.protocol
        prior = self.deployments.artifacts.read(evidence_key)
        if prior is not None and (prior["engine"] != engine or prior["target"] != target):
            raise ValueError("cascade recovery target changed after its effect was journaled")
        if prior is None:
            self.deployments.artifacts.write(evidence_key, {"engine": engine, "target": target,
                "before": config_before, "runtime_before": self.observe().get("runtime_id"),
                "request_digest": canonical_digest(request.to_document())})
        self._store.update(request, phase="applying")
        try:
            authorization = self._gate.authorize_participant(request.operation_id)
            if self._apply_config(self._state_reader(), authorization) is not True:
                raise RuntimeError("canonical cascade configuration apply did not confirm")
            current_engine, current_config = self._context()
            observed = self.observe()
            if current_engine != engine or current_config != target or observed.get("engine_active") is not True:
                raise RuntimeError("active cascade configuration differs from prepared canonical output")
            if observed.get("config_sha256") != current_config:
                raise RuntimeError("cascade process/config proof is unavailable")
            if config_before != target and observed.get("runtime_id") == self.deployments.artifacts.read(evidence_key)["runtime_before"]:
                raise RuntimeError("cascade config changed without a confirmed engine restart")
            receipt = self._receipt(request, "applied", engine, current_config, record["receipt"].get("material_digest"))
            self._store.update(request, phase="applied", after_engine_identity=engine,
                               after_config_identity=current_config, receipt=receipt.to_document())
            return receipt
        except Exception:
            self._store.update(request, phase="recovery_required")
            raise

    def query(self, request):
        self._validate_local(request)
        record = self._store.record(request)
        if record is not None and record["phase"] in {"applying", "recovery_required"} and not record["rollback_requested"]:
            evidence = self.deployments.artifacts.read("effect-" + request.operation_id + "-" + request.protocol)
            if evidence is not None and evidence["request_digest"] == canonical_digest(request.to_document()):
                engine, config = self._context()
                observed = self.observe()
                live = engine == evidence["engine"] and observed.get("engine_active") is True and observed.get("config_sha256") == config
                changed_process = observed.get("runtime_id") != evidence["runtime_before"]
                if live and config == evidence["target"] and (changed_process or config == evidence["before"]):
                    receipt = self._receipt(request, "applied", engine, config, record["receipt"].get("material_digest"))
                    self._store.reconcile_application(request, receipt)
                    return "applied", receipt
                if live and config == evidence["before"] and config != evidence["target"]:
                    self._store.reconcile_application(request)
                    return "not_applied", None
        return super().query(request)

    def rollback(self, request):
        result = super().rollback(request)
        if request.kind == "cascade_save" and request.plan["previous"] is None:
            self.deployments.discard(request)
        return result

    def probe_state(self, request):
        self._validate_live(request)
        engine, config = self._context()
        observed = self.observe()
        if observed.get("engine_active") is not True or observed.get("config_sha256") != config:
            raise RuntimeError("cascade engine is not active with the expected configuration")
        if self.preview(self._state_reader()) != config:
            raise RuntimeError("cascade active configuration differs from canonical state")
        scope = self._credentials.load(request.target_id)
        subject = scope.technical_subject(self.participant_id, request.protocol, request.role, request.operation_id)
        raw = self.stats_reader()
        return {"receipt": self._receipt(request, "applied", engine, config).to_document(),
                "runtime_id": observed["runtime_id"], "counter": raw.get(subject.email, 0),
                "policy_digest": policy_digest(self._state_reader())}

    def publication(self, request):
        evidence = self.probe_state(request)
        document = self.deployments.document(request)
        if request.role != "entry":
            raise ValueError("only the entry participant can publish client profiles")
        state = self._state_reader()
        scope = self._credentials.load(request.target_id)
        builder = ManagedNodeProfileBuilder(protocols=self.protocols)
        profiles = []
        for business in state.users:
            if not access_status(business)[0] or request.protocol in business.disabled_protocols:
                continue
            subject = scope.subject(self.participant_id, request.protocol, "entry", business)
            for profile in builder._plugin_profiles(state, self.participant_id, subject, request.protocol):
                profiles.append(replace(profile, user_uuid=business.uuid, route_id=request.target_id,
                                        stable_id=canonical_digest({"route": request.target_id, "protocol": request.protocol,
                                                                    "user": business.uuid})).to_document())
        return {**evidence, "profiles": profiles, "probe_endpoint": document["endpoint"]}

    def _validate_live(self, request):
        self._validate_local(request)
        self.deployments.document(request)
        record = self._require_record(request)
        if record["phase"] not in {"applied", "finalized"}:
            raise ValueError("cascade publication requires confirmed participant apply")

    def finalize(self, request, commit_digest):
        # Promotion precedes snapshot deletion; repeat calls repair interrupted finalization.
        self._validate_local(request)
        record = self._require_record(request)
        if record["phase"] not in {"applied", "finalized"}:
            raise ValueError("cascade cannot be activated before participant apply")
        if self.participant_id == "base":
            operation = self._records.find_operation(request.operation_id)
            if operation is None or operation.state != "succeeded" or canonical_digest(operation.to_document()) != commit_digest:
                raise ValueError("cascade coordinator has not committed")
        if not isinstance(commit_digest, str) or len(commit_digest) != 64 or any(c not in "0123456789abcdef" for c in commit_digest):
            raise ValueError("invalid cascade coordinator commit digest")
        self.deployments.finalize(request)
        if self.participant_id != "base":
            self.finalize_state(request)
        return super().finalize(request, commit_digest)
