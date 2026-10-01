"""Application service for configured Hydra nodes."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
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
from hydra.core.state_nodes import MANAGEMENT_ACTIVE, MANAGEMENT_WITHDRAWN, NodeConfig
from hydra.services.nodes.credentials import NodeControlCredentials
from hydra.services.nodes.control_client import NodeControlPort
from hydra.services.nodes.lifecycle import NodeLifecycle
from hydra.services.nodes.onboarding import NodeOnboarding, NodeProvisioningPort
from hydra.services.nodes.observation import (
    CONTROL_OK,
    STAGE_UPGRADE,
    NodeObservation,
    NodeObservationStore,
    published_coverage,
    record_check,
    record_current_apply_error,
    record_sync,
)
from hydra.services.nodes.reconciler import NodeSnapshotReconciler, NodeSyncResult
from hydra.services.nodes.revision import revision_supports_node_mode
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.nodes.ssh_auth import SshPasswordAuth
from hydra.services.node_traffic_accounting import apply_node_traffic_reports


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
        self.lifecycle = NodeLifecycle(
            # Indirection, not a captured reference: replacing the writer on the manager
            # (a failure-injection test, a future adapter) must affect these operations.
            state_reader=lambda: self.state_reader(),
            state_updater=lambda mutator: self.state_updater(mutator),
            find_node=self._find_node,
            refresh=self.refresh,
            collect_traffic=self.collect_traffic,
            stop_publication=self._reconciler.stop_publication,
            snapshot_store=snapshot_store,
            observations_store=observations,
            uninstall_remote=uninstall_remote,
            forget_node_credentials=forget_node_credentials,
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
        if node.withdrawn or node.published_generation <= 0 or not node.published_digest:
            return None
        return self.snapshot_store.load(node_id, node.published_generation, node.published_digest)

    def add_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
        auth: SshPasswordAuth | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> NodeSyncResult:
        return self._onboarding().add(
            node,
            base_url=base_url,
            confirm_fingerprint=confirm_fingerprint,
            vk_cookie_source=vk_cookie_source,
            auth=auth,
            progress=progress,
        )

    def resume_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
    ) -> NodeSyncResult:
        """Continue a node that was installed but never got its control identity."""
        return self._onboarding().resume(
            node,
            base_url=base_url,
            confirm_fingerprint=confirm_fingerprint,
            vk_cookie_source=vk_cookie_source,
        )

    def _onboarding(self) -> NodeOnboarding:
        # Dependencies are checked per entry point, not here: a node whose configuration is
        # invalid or already managed must be rejected on its own merits, and resuming does
        # not need the cleanup callbacks an install does.
        return NodeOnboarding(
            state_reader=self.state_reader,
            state_updater=self.state_updater,
            bootstrap=self.bootstrap,
            uninstall_remote=self.uninstall_remote,
            forget_node_credentials=self.forget_node_credentials,
            refresh=self.refresh,
            import_remote_cookies=self.import_remote_cookies,
        )

    def remove_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        return self.lifecycle.remove_node(node_id, confirmed=confirmed)

    def detach_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        return self.lifecycle.detach_node(node_id, confirmed=confirmed)

    def withdraw_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        return self.lifecycle.withdraw_node(node_id, confirmed=confirmed)

    def restore_node(self, node_id: str) -> NodeSyncResult:
        return self.lifecycle.restore_node(node_id)

    def set_appearance(
        self,
        node_id: str,
        *,
        display_id: str | None = None,
        name: str | None = None,
        region: str | None = None,
    ) -> NodeConfig:
        return self.lifecycle.set_appearance(node_id, display_id=display_id, name=name, region=region)

    def import_vk_cookies(self, node_id: str, source_path: str) -> None:
        if self.import_remote_cookies is None:
            raise RuntimeError("node cookie import is unavailable")
        node = deepcopy(self._find_node(self.state_reader(), node_id))
        self.import_remote_cookies(node, source_path)

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
        installed = health.get("revision")
        installed = installed[:64] if isinstance(installed, str) and installed.isprintable() else ""
        record_check(self.observations_store, node, generation, last_error, installed)
        return {
            "ok": True,
            "node_id": node_id,
            "generation": generation,
            "contract_version": NODE_CONTRACT_VERSION,
            "last_error": last_error[:2048],
            "installed_revision": installed,
        }

    def refresh(self, node_id: str, *, force: bool = False) -> NodeSyncResult:
        try:
            result = self._reconciler.refresh(node_id, force=force)
        except Exception as exc:
            if self.observations_store is not None:
                node = self._find_node(self.state_reader(), node_id)
                self.observations_store.failed(node_id, exc, target_revision=node.revision)
            raise
        record_sync(
            self.observations_store,
            self._find_node(self.state_reader(), node_id),
            result,
            lambda: published_coverage(self.published_export(self.state_reader(), node_id)),
        )
        record_current_apply_error(
            self.observations_store,
            self.client_for(self._find_node(self.state_reader(), node_id)),
        )
        return result

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
        self._store_protocol(node_id, name, spec)
        return self.refresh(node_id)

    def save_protocol(self, node_id: str, name: str, spec: NodeProtocolSpec) -> dict[str, object]:
        """Save validated public settings, then try to apply them.

        Saving and applying are separate results: an offline node keeps the operator's
        intent and applies it on the next successful contact, so this returns what
        happened instead of raising away an already-saved change.
        """
        self._store_protocol(node_id, name, spec)
        try:
            result = self.refresh(node_id)
        except Exception as exc:
            return {
                "node_id": node_id,
                "protocol": name,
                "saved": True,
                "applied": False,
                "error": type(exc).__name__,
                "detail": str(exc)[:512],
            }
        return {
            "node_id": node_id,
            "protocol": name,
            "saved": True,
            "applied": True,
            "status": result.status,
            "generation": result.generation,
            "coverage": dict(result.coverage),
            "warnings": list(result.warnings),
        }

    def _store_protocol(self, node_id: str, name: str, spec: NodeProtocolSpec) -> None:
        spec.validate(label=f"nodes.{node_id}.protocols.{name}")

        def update(state: AppState) -> None:
            node = self._find_node(state, node_id)
            node.protocols[name] = deepcopy(spec)
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(update)

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
            if node.withdrawn:
                # A withdrawn node has no users, so it has nothing left to report.
                continue
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
    def _find_node(state: AppState, node_id: str) -> NodeConfig:
        for node in state.nodes:
            if node.id == node_id:
                return node
        raise ValueError(f"managed node {node_id} was not found")


__all__ = ["NodeManager"]
