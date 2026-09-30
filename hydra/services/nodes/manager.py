"""Application service for configured Hydra nodes."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Protocol

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.contracts.node_validation import (
    NODE_CONTRACT_VERSION,
    NodeContractError,
    checked_node_branch,
    checked_node_revision,
)
from hydra.core.configuration_names import normalize_configuration_name, validate_configuration_key
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.credentials import NodeControlCredentials
from hydra.services.nodes.control_client import NodeControlPort
from hydra.services.nodes.observation import (
    CONTROL_OK,
    STAGE_UPGRADE,
    NodeObservation,
    NodeObservationStore,
)
from hydra.services.nodes.reconciler import NodeSnapshotReconciler, NodeSyncResult
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.node_traffic_accounting import apply_node_traffic_reports, retire_node_traffic


class NodeProvisioningPort(Protocol):
    def resolve_revision(self, branch: str) -> str: ...

    def install(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        branch: str,
        revision: str,
        confirm_fingerprint: Callable[[str], bool],
    ) -> str: ...

    def provision_control_identity(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        base_url: str,
        control_port: int,
    ) -> NodeControlCredentials: ...


class NodeManager:
    """Own node operations, while keeping all host and network effects injected."""

    def __init__(
        self,
        *,
        state_reader: Callable[[], AppState],
        state_updater: Callable,
        client_for: Callable[[NodeConfig], NodeControlPort],
        snapshot_store: NodeSnapshotStore,
        bootstrap: NodeProvisioningPort | None = None,
        uninstall_remote: Callable[[NodeConfig], None] | None = None,
        forget_node_credentials: Callable[[str], None] | None = None,
        import_remote_cookies: Callable[[NodeConfig, str], None] | None = None,
        observations: NodeObservationStore | None = None,
    ):
        self.state_reader = state_reader
        self.state_updater = state_updater
        self.client_for = client_for
        self.snapshot_store = snapshot_store
        self.bootstrap = bootstrap
        self.uninstall_remote = uninstall_remote
        self.forget_node_credentials = forget_node_credentials
        self.import_remote_cookies = import_remote_cookies
        self.observations_store = observations
        self._reconciler = NodeSnapshotReconciler(
            state_updater=state_updater,
            client_for=client_for,
            snapshot_store=snapshot_store,
        )

    def list_nodes(self, state: AppState) -> list[NodeConfig]:
        return deepcopy(state.nodes)

    def observations(self) -> dict[str, NodeObservation]:
        """Last known runtime state per node; never part of the desired configuration."""
        if self.observations_store is None:
            return {}
        return self.observations_store.load()

    def resolve_revision(self, branch: str) -> str:
        branch = checked_node_branch(branch, context="branch")
        if self.bootstrap is None:
            raise RuntimeError("node branch resolution is unavailable")
        return checked_node_revision(self.bootstrap.resolve_revision(branch), context="revision")

    def published_export(self, state: AppState, node_id: str) -> NodeClientExport | None:
        node = self._find_node(state, node_id)
        if node.published_generation <= 0 or not node.published_digest:
            return None
        return self.snapshot_store.load(node_id, node.published_generation, node.published_digest)

    def add_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
    ) -> NodeSyncResult:
        bootstrap, uninstall_remote, forget_credentials = self._provisioning_dependencies()
        if vk_cookie_source is not None:
            from hydra.services.nodes.cookies import load_cookie_file

            if self.import_remote_cookies is None:
                raise RuntimeError("node cookie import is unavailable")
            load_cookie_file(vk_cookie_source)
        candidate = deepcopy(node)
        candidate.validate(path=f"nodes.{candidate.id}")
        if candidate.control_fingerprint or candidate.generation or candidate.published_generation:
            raise ValueError("new node must not contain control credentials or runtime generations")
        if candidate.desired_digest or candidate.published_digest:
            raise ValueError("new node must not contain published snapshot digests")
        branch = checked_node_branch(candidate.branch, context="branch")
        revision = checked_node_revision(candidate.revision, context="revision")
        if not isinstance(base_url, str) or not base_url.strip() or not callable(confirm_fingerprint):
            raise ValueError("base_url and SSH fingerprint confirmation are required")
        if any(item.id == candidate.id for item in self.state_reader().nodes):
            raise ValueError(f"managed node {candidate.id} already exists")

        bootstrap.install(
            node_id=candidate.id,
            address=candidate.address,
            ssh_port=candidate.ssh_port,
            branch=branch,
            revision=revision,
            confirm_fingerprint=confirm_fingerprint,
        )
        try:
            credentials = bootstrap.provision_control_identity(
                node_id=candidate.id,
                address=candidate.address,
                ssh_port=candidate.ssh_port,
                base_url=base_url,
                control_port=candidate.control_port,
            )
        except Exception as exc:
            raise RuntimeError(
                "node was installed but control identity provisioning failed; retry with the same node ID"
            ) from exc
        candidate.control_fingerprint = credentials.node_fingerprint
        candidate.validate(path=f"nodes.{candidate.id}")

        def register(state: AppState) -> None:
            if any(item.id == candidate.id for item in state.nodes):
                raise ValueError(f"managed node {candidate.id} already exists")
            state.nodes.append(deepcopy(candidate))

        try:
            self.state_updater(register)
        except Exception as exc:
            try:
                uninstall_remote(candidate)
                forget_credentials(candidate.id)
            except Exception as cleanup_error:
                raise RuntimeError("node registration failed and remote cleanup did not complete") from exc
            raise
        try:
            if vk_cookie_source is not None:
                self.import_vk_cookies(candidate.id, vk_cookie_source)
            return self.refresh(candidate.id)
        except Exception as exc:
            raise RuntimeError("node was provisioned but its initial snapshot was not published") from exc

    def remove_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node removal requires explicit confirmation")
        if self.uninstall_remote is None or self.forget_node_credentials is None:
            raise RuntimeError("node removal is unavailable")
        node = deepcopy(self._find_node(self.state_reader(), node_id))
        self.uninstall_remote(node)
        return self._remove_local_node(node, status="removed")

    def detach_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        """Forget local publication only; an offline remote runtime is NOT stopped."""
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node detach requires explicit confirmation")
        if self.forget_node_credentials is None:
            raise RuntimeError("node credential cleanup is unavailable")
        node = deepcopy(self._find_node(self.state_reader(), node_id))
        result = self._remove_local_node(node, status="detached")
        result["remote_cleanup"] = False
        return result

    def import_vk_cookies(self, node_id: str, source_path: str) -> None:
        if self.import_remote_cookies is None:
            raise RuntimeError("node cookie import is unavailable")
        node = deepcopy(self._find_node(self.state_reader(), node_id))
        self.import_remote_cookies(node, source_path)

    def _remove_local_node(self, node: NodeConfig, *, status: str) -> dict[str, object]:
        node_id = node.id

        def remove(state: AppState) -> None:
            current = self._find_node(state, node_id)
            if not self._same_removal_target(current, node):
                raise RuntimeError("node configuration changed during remote removal")
            state.nodes.remove(current)
            retire_node_traffic(state, node_id)

        self.state_updater(remove)
        if self.observations_store is not None:
            self.observations_store.forget(node_id)
        warnings: list[str] = []
        if node.published_generation and node.published_digest:
            try:
                self.snapshot_store.delete(node_id, node.published_generation, node.published_digest)
            except Exception as exc:
                warnings.append(f"snapshot:{type(exc).__name__}")
        try:
            if self.forget_node_credentials is None:
                raise RuntimeError("node credential cleanup is unavailable")
            self.forget_node_credentials(node_id)
        except Exception as exc:
            warnings.append(f"credentials:{type(exc).__name__}")
        result: dict[str, object] = {"node_id": node_id, "status": status}
        if warnings:
            result["cleanup_warnings"] = warnings
        return result

    def check(self, node_id: str) -> dict[str, object]:
        node = self._find_node(self.state_reader(), node_id)
        client = self.client_for(node)
        try:
            health = client.health()
            generation = health.get("generation")
            if (
                not isinstance(health.get("ok"), bool)
                or not health["ok"]
                or health.get("node_id") != node_id
                or health.get("contract_version") != NODE_CONTRACT_VERSION
                or type(generation) is not int
                or generation < 0
            ):
                raise RuntimeError("node health or contract check failed")
            diagnostics = client.diagnostics()
        except Exception as exc:
            if self.observations_store is not None:
                self.observations_store.failed(
                    node_id,
                    exc,
                    target_revision=node.revision,
                )
            raise
        last_error = diagnostics.get("last_error", "")
        if not isinstance(last_error, str):
            last_error = ""
        if self.observations_store is not None:
            if last_error:
                # The node answered, so this is not a connectivity problem: it is the
                # node's own last apply failure, which is what the operator must see.
                self.observations_store.record(
                    node_id,
                    control=CONTROL_OK,
                    stage="apply",
                    code="node_apply_error",
                    message=last_error[:2048],
                    applied_generation=generation,
                    target_revision=node.revision,
                )
            else:
                self.observations_store.succeeded(
                    node_id,
                    applied_generation=generation,
                    target_revision=node.revision,
                )
        return {
            "ok": True,
            "node_id": node_id,
            "generation": generation,
            "contract_version": NODE_CONTRACT_VERSION,
            "last_error": last_error[:2048],
        }

    def refresh(self, node_id: str, *, force: bool = False) -> NodeSyncResult:
        try:
            result = self._reconciler.refresh(node_id, force=force)
        except Exception as exc:
            if self.observations_store is not None:
                node = self._find_node(self.state_reader(), node_id)
                self.observations_store.failed(node_id, exc, target_revision=node.revision)
            raise
        self._record_sync(node_id, result)
        return result

    def _record_sync(self, node_id: str, result: NodeSyncResult) -> None:
        if self.observations_store is None:
            return
        node = self._find_node(self.state_reader(), node_id)
        self.observations_store.succeeded(
            node_id,
            applied_generation=node.generation,
            published_generation=node.published_generation,
            coverage=dict(result.coverage),
            warnings=tuple(result.warnings),
            target_revision=node.revision,
        )

    def change_name(self, node_id: str, name: str, *, region: str | None = None) -> NodeConfig:
        result: NodeConfig | None = None

        def rename(state: AppState) -> None:
            nonlocal result
            node = self._find_node(state, node_id)
            node.name = name
            if region is not None:
                node.region = region
            node.validate(path=f"nodes.{node_id}")
            result = deepcopy(node)

        self.state_updater(rename)
        if result is None:
            raise RuntimeError("node rename did not complete")
        return result

    def change_profile_name(self, node_id: str, key: str, name: str) -> None:
        key = validate_configuration_key(key)
        name = normalize_configuration_name(name)

        def rename(state: AppState) -> None:
            node = self._find_node(state, node_id)
            if name:
                node.profile_names[key] = name
            else:
                node.profile_names.pop(key, None)
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(rename)

    def change_update_target(self, node_id: str, *, branch: str, revision: str) -> None:
        try:
            branch = checked_node_branch(branch, context="branch")
            revision = checked_node_revision(revision, context="revision")
        except ValueError as exc:
            raise NodeContractError(str(exc)) from exc

        def change(state: AppState) -> None:
            node = self._find_node(state, node_id)
            node.branch, node.revision = branch, revision
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(change)

    def change_protocol(self, node_id: str, name: str, spec: NodeProtocolSpec) -> NodeSyncResult:
        spec.validate(label=f"nodes.{node_id}.protocols.{name}")
        self.check(node_id)

        def update(state: AppState) -> None:
            node = self._find_node(state, node_id)
            node.protocols[name] = deepcopy(spec)
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(update)
        return self.refresh(node_id)

    def update(self, node_id: str) -> dict[str, object]:
        node = self._find_node(self.state_reader(), node_id)
        branch = checked_node_branch(node.branch, context="branch")
        revision = checked_node_revision(node.revision, context="revision")
        result = self.client_for(node).upgrade(branch=branch, revision=revision)
        already_scheduled = result.get("already_scheduled", False)
        if (
            result.get("status") != "scheduled"
            or result.get("branch") != branch
            or result.get("revision") != revision
            or type(already_scheduled) is not bool
        ):
            raise RuntimeError("node returned an invalid upgrade schedule")
        response: dict[str, object] = {
            "node_id": node_id,
            "status": "scheduled",
            "branch": branch,
            "revision": revision,
        }
        if already_scheduled:
            response["already_scheduled"] = True
        if self.observations_store is not None:
            # Scheduling is not completion: the revision is the target until the node
            # reports the one it actually runs.
            self.observations_store.record(
                node_id,
                stage=STAGE_UPGRADE,
                code="",
                message="",
                upgrade="scheduled",
                target_revision=revision,
            )
        return response

    def reconcile_all(self) -> dict[str, dict[str, object]]:
        """Best-effort full-state push; offline nodes never roll back base mutations."""
        results: dict[str, dict[str, object]] = {}
        for node in self.state_reader().nodes:
            try:
                result = self.refresh(node.id)
            except Exception as exc:
                results[node.id] = {"status": "failed", "error": type(exc).__name__}
                continue
            results[node.id] = {
                "status": result.status,
                "generation": result.generation,
                "sha256": result.sha256,
            }
        return results

    def collect_traffic(self) -> None:
        """Fetch outside the state lock, then atomically credit validated samples."""
        reports = self.traffic_reports()
        if not reports:
            return

        def credit(state: AppState) -> None:
            nodes = {node.id: node for node in state.nodes}
            current_reports = [
                report
                for report in reports
                if report.node_id in nodes and report.generation == nodes[report.node_id].generation
            ]
            apply_node_traffic_reports(state, current_reports)

        self.state_updater(credit)

    def traffic_reports(self) -> tuple[NodeTrafficReport, ...]:
        """Return current absolute reports; offline nodes retain their last sample."""
        reports: list[NodeTrafficReport] = []
        for node in self.state_reader().nodes:
            try:
                self.refresh(node.id)
                current = self._find_node(self.state_reader(), node.id)
                report = self.client_for(current).traffic_report()
                report.validate()
                if report.node_id == node.id and report.generation == current.generation:
                    reports.append(report)
            except Exception:
                # Traffic collection is best-effort and never blocks local accounting.
                continue
        return tuple(reports)

    def _provisioning_dependencies(
        self,
    ) -> tuple[NodeProvisioningPort, Callable[[NodeConfig], None], Callable[[str], None]]:
        if self.bootstrap is None or self.uninstall_remote is None or self.forget_node_credentials is None:
            raise RuntimeError("node provisioning is unavailable")
        return self.bootstrap, self.uninstall_remote, self.forget_node_credentials

    @staticmethod
    def _same_removal_target(current: NodeConfig, expected: NodeConfig) -> bool:
        return (
            current.id == expected.id
            and current.address == expected.address
            and current.ssh_port == expected.ssh_port
            and current.control_port == expected.control_port
            and current.control_fingerprint == expected.control_fingerprint
        )

    @staticmethod
    def _find_node(state: AppState, node_id: str) -> NodeConfig:
        for node in state.nodes:
            if node.id == node_id:
                return node
        raise ValueError(f"managed node {node_id} was not found")


__all__ = ["NodeManager"]
