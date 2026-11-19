"""Isolated production cascade owners with injected engine and network boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
import time
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

from hydra.contracts.managed_node_models import NodeDefinition, ProtocolAssignment
from hydra.contracts.managed_node_observations import CheckResult
from hydra.core.host import HostBackend
from hydra.core.singbox_config import generate_config
from hydra.core.state_managed_nodes import ManagedNodesState, managed_nodes_from_extensions, store_managed_nodes
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.container import PluginContainer
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_deployment import CascadeDeploymentStore
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import CascadePreparationStore, ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.cascade_production_participant import ProductionCascadeParticipant
from hydra.services.managed_nodes.cascade_rendering import ManagedNodeCascadeRenderer
from hydra.services.managed_nodes.cascade_runtime_service import ManagedNodeCascadeRuntime
from hydra.services.managed_nodes.cascade_publication import CascadePathPublisher, CascadePublicationStore
from hydra.services.managed_nodes.cascades import ManagedNodeCascadeService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.rendering import ProductionRuntimeContributions
from hydra.services.protocols import ProtocolService
from hydra.utils.crypto import derive_hex_key


USER = User("one@example.test", "7a8f5195-7749-451c-9ff0-a9c514d2bca1")
ENGINE = "1" * 64


class LabNode:
    def __init__(self, root, identity, protocols=("vless", "anytls"), *, engine=None):
        self.identity, self.host, self.root = identity, HostBackend(), root
        self.raw, self.applies, self.engine = {}, 0, engine
        self.state = AppState(users=[copy.deepcopy(USER)], protocols={name: PluginState(
            enabled=True, installed=True, port=443 if name == "vless" else 8443,
            config={"domain": identity + ".example.test", "cert_file": str(root / "cert.pem"),
                    "key_file": str(root / "key.pem"), "security": "tls", "xhttp_path": "/api/test",
                    "xhttp_mode": "stream-up"}) for name in protocols})
        root.mkdir(parents=True)
        (root / "cert.pem").write_text("test certificate")
        (root / "key.pem").write_text("test key")
        self.config = root / "config.json"
        self.gate = ManagedNodeApplyGate(state_reader=self.read, participant_id=identity,
                                         lock_path=root / "gate.lock", authenticated_participant=lambda _: identity)
        self.records = ManagedNodeRecords(state_reader=self.read, state_updater=self.gate.wrap_state_updater(self.update))
        self.credentials = CascadeCredentialStore(host=self.host, root=root / "credentials")
        self.transactions = CascadeParticipantStore(host=self.host, root=root / "transactions")
        self.deployments = CascadeDeploymentStore(host=self.host, root=root / "deployments", participant_id=identity,
                                                  credentials=self.credentials, transactions=self.transactions)
        renderer = ManagedNodeCascadeRenderer(participant_id=identity, credentials=self.credentials,
                                               restore_context_provider=self.transactions.restoration_contexts)
        self.contributions = ProductionRuntimeContributions(renderer, deployments=self.deployments)
        self.plugins = PluginContainer([VlessXhttpPlugin(), AnyTLSPlugin()], host=self.host,
                                        runtime_contributions=self.contributions)
        self.protocols = ProtocolService(SimpleNamespace(), self.plugins)
        self.write_config()
        preparation = ManagedNodeCascadePreparationOwner(records=self.records, state_reader=self.read,
            credentials=self.credentials, store=CascadePreparationStore(host=self.host, root=root / "preparations"),
            participant_id=identity)
        self.owner = ProductionCascadeParticipant(
            participant_id=identity, records=self.records, state_reader=self.read, gate=self.gate,
            store=self.transactions, preparation=preparation, credentials=self.credentials,
            context_reader=self.context, apply_config=self.apply, client_material=self.material,
            capture_restore_context=lambda state, operation, request: self.contributions.capture_cascade_scope(
                state, request, request.route if operation.plan["previous"] is not None else None),
            capture_remove_config_identity=lambda state, request: self.preview(state),
            deployments=self.deployments, preview=self.preview, observe=self.observe,
            capability_probe=lambda protocol, digest: digest == ENGINE,
            final_accounting=lambda: None, protocols=self.protocols, finalize_state=self.finalize_state,
            stats_reader=lambda: copy.deepcopy(self.raw),
        )

    def read(self):
        return copy.deepcopy(self.state)

    def update(self, mutator):
        current = self.read()
        result = mutator(current)
        current.revision += 1
        self.state = current
        return self.read(), result

    def render(self, state):
        return generate_config(state, self.plugins.collect_fragments(state))

    def preview(self, state):
        return hashlib.sha256(json.dumps(self.render(state), indent=2, ensure_ascii=False).encode()).hexdigest()

    def write_config(self):
        self.config.write_text(json.dumps(self.render(self.read()), indent=2, ensure_ascii=False))

    def context(self):
        return ENGINE, hashlib.sha256(self.config.read_bytes()).hexdigest()

    def observe(self):
        return {"engine_active": True, "config_sha256": self.context()[1],
                "runtime_id": hashlib.sha256(f"{self.identity}:{self.applies}".encode()).hexdigest()}

    def apply(self, state, authorization):
        with self.gate.application(authorization):
            self.applies += 1
            self.write_config()
        return True

    def material(self, state, protocol, user):
        document = json.loads(self.protocols.singbox_client_config(state, protocol, user))
        return next(item for item in document["outbounds"] if item.get("type") == protocol)

    def finalize_state(self, request):
        def mutate(state):
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            routes = [item for item in namespace.cascades if item.id != request.target_id]
            if request.kind == "cascade_save":
                routes.append(request.route)
            store_managed_nodes(state.feature_extensions, replace(namespace, cascades=routes))
        self.update(mutate)


class LabClient:
    def __init__(self, node):
        self.node = node

    def cascade_capabilities(self, _deadline):
        return self.node.owner.capabilities()

    def __getattr__(self, name):
        operations = {"snapshot": "ensure_snapshot", "material": "technical_material", "status": "query"}
        action = name.removeprefix("cascade_")
        owner_action = operations.get(action, action)
        def call(*args):
            result = getattr(self.node.owner, owner_action)(*args[:-1])
            if action == "status":
                return SimpleNamespace(state=result[0], receipt=result[1])
            return result
        return call


class CascadeLab:
    def __init__(self, root, *, topology=("base", "exit"), protocols=("vless", "anytls"), probe=True,
                 node_factory=LabNode):
        self.nodes = {identity: node_factory(root / identity, identity, protocols) for identity in sorted({"base", *topology})}
        base = self.nodes["base"]
        for identity in self.nodes:
            if identity != "base":
                base.records.put_definition(NodeDefinition(identity, identity, "203.0.113.4", "root", "dev", "a" * 40,
                    25555, [ProtocolAssignment(name, {"port": 443}) for name in protocols], "node/" + identity))
        self.publications = CascadePublicationStore(host=base.host, root=root / "publications")
        self.probe_ok = probe
        def probe_client(material, *, node_id, deadline):
            exit = self.nodes[topology[1]]
            for document in exit.deployments.selected(exit.read()):
                request = exit.deployments._request(document)
                if request.protocol == material.protocol:
                    scope = exit.credentials.load(request.target_id)
                    subject = scope.technical_subject(exit.identity, request.protocol, request.role, request.operation_id)
                    exit.raw[subject.email] = exit.raw.get(subject.email, 0) + 100
            return CheckResult("connection", node_id, "ok" if self.probe_ok else "error", reason="" if self.probe_ok else "exit unavailable")
        self.runtime = ManagedNodeCascadeRuntime(records=base.records, local=base.owner, credentials=base.credentials,
            client_factory=lambda identity: LabClient(self.nodes[identity]), publication_store=self.publications,
            path_publisher_factory=lambda invoke, request: CascadePathPublisher(records=base.records, state_reader=base.read,
                invoke=invoke, request=request, probe_client=SimpleNamespace(probe_client=probe_client), store=self.publications))
        self.ids = iter(f"cascade-{number}" for number in range(1, 100))
        self.service = ManagedNodeCascadeService(records=base.records, runtime=self.runtime,
            credentials=base.credentials, operation_id_factory=lambda: next(self.ids))


@contextmanager
def management_transport(lab):
    from hydra.services.managed_nodes.agent import ManagedNodeAgent
    from hydra.services.managed_nodes.client import ManagedNodeClient
    from hydra.services.managed_nodes.transport import ManagedNodeServer
    from hydra.services.managed_nodes.identity import ManagementIdentity, create_certificate_pair, certificate_fingerprint
    from hydra.contracts.managed_node_observations import NodeSample
    clients, servers = {}, []
    try:
        for name, node in lab.nodes.items():
            if name == "base":
                continue
            client_cert, client_key = create_certificate_pair("base", role="client")
            server_cert, server_key = create_certificate_pair(name, role="server", address="127.0.0.1")
            for filename, data in (("client.crt", client_cert), ("client.key", client_key),
                                   ("server.crt", server_cert), ("server.key", server_key)):
                node.host.atomic_write(node.root / filename, data, mode=0o600)
            identity = ManagementIdentity(name, "127.0.0.1", 0, node.root / "server.crt", node.root / "server.key",
                                          node.root / "client.crt", certificate_fingerprint(client_cert), ("127.0.0.1",))
            agent = ManagedNodeAgent(node_id=name, state_provider=lambda n=name: NodeSample(n),
                                      submit_provider=None, operation_provider=lambda _: None,
                                      profiles_provider=None, cascade_participant=node.owner)
            server = ManagedNodeServer(identity, agent, bind_host="127.0.0.1", request_timeout=30)
            server.start()
            servers.append(server)
            clients[name] = ManagedNodeClient(host="127.0.0.1", port=server.port, node_id=name,
                certificate=node.root / "client.crt", private_key=node.root / "client.key", pinned_server_certificate=server_cert)
        original = lab.runtime._client_factory
        lab.runtime._client_factory = lambda name: clients[name]
        yield clients
    finally:
        for server in servers:
            server.close()
        if "original" in locals():
            lab.runtime._client_factory = original
