"""Desired-configuration lifecycle of a managed node: appearance, withdraw, removal.

These operations change what the base intends for a node, not what the node runs right
now. Keeping them apart from reconciliation keeps both readable: the reconciler answers
"what does the node have to apply", while this module answers "what does the operator
want this node to be". Every effect is injected, so no host call lives here.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass

from hydra.core.state_models import AppState
from hydra.core.state_nodes import MANAGEMENT_ACTIVE, MANAGEMENT_WITHDRAWN, NodeConfig
from hydra.services.nodes.observation import NodeObservationStore
from hydra.services.nodes.reconciler import NodeSyncResult
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.node_traffic_accounting import retire_node_traffic


@dataclass
class NodeLifecycle:
    """Apply operator intent about a node's identity, service state and existence."""

    state_reader: Callable[[], AppState]
    state_updater: Callable
    find_node: Callable[[AppState, str], NodeConfig]
    refresh: Callable[[str], NodeSyncResult]
    collect_traffic: Callable[[], None]
    stop_publication: Callable[[str], None]
    snapshot_store: NodeSnapshotStore
    observations_store: NodeObservationStore | None = None
    uninstall_remote: Callable[[NodeConfig], None] | None = None
    forget_node_credentials: Callable[[str], None] | None = None

    # ── identity ────────────────────────────────────────────────────────────

    def set_appearance(
        self,
        node_id: str,
        *,
        display_id: str | None = None,
        name: str | None = None,
        region: str | None = None,
    ) -> NodeConfig:
        """Rename the operator-facing identity only.

        Certificates, exports and traffic accounting are keyed by the technical id, so
        changing what the operator sees never touches trust or history.
        """
        result: NodeConfig | None = None

        def rename(state: AppState) -> None:
            nonlocal result
            node = self.find_node(state, node_id)
            if display_id is not None:
                node.display_id = display_id
            if name is not None:
                node.name = name
            if region is not None:
                node.region = region
            node.validate(path=f"nodes.{node_id}")
            result = deepcopy(node)

        self.state_updater(rename)
        if result is None:
            raise RuntimeError("node appearance change did not complete")
        return result

    # ── service state ───────────────────────────────────────────────────────

    def withdraw_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        """Take the node out of subscriptions and purge its users and transports.

        The withdrawal is desired configuration, so the next scheduled sync keeps it: an
        empty runtime travels to the node instead of the users it used to serve. The node
        itself stays managed, which is what makes an explicit return possible.
        """
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node withdrawal requires explicit confirmation")
        result: dict[str, object] = {"node_id": node_id, "status": "withdrawn", "remote_cleanup": False}
        # Final accounting attempt before the node's counters disappear with its users.
        try:
            self.collect_traffic()
        except Exception as exc:
            result["accounting_warning"] = type(exc).__name__

        def withdraw(state: AppState) -> None:
            node = self.find_node(state, node_id)
            node.management = MANAGEMENT_WITHDRAWN
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(withdraw)
        # The base owns the subscription, so the node leaves it now even if the purge
        # itself has to wait for the next successful contact.
        try:
            self.stop_publication(node_id)
        except Exception as exc:
            result["publication_error"] = type(exc).__name__
        try:
            sync = self.refresh(node_id)
        except Exception as exc:
            # The node is already out of subscriptions; the purge itself is still
            # pending, and the next sync retries it without restoring the users.
            result["error"] = type(exc).__name__
            result["error_detail"] = str(exc)[:512]
            return result
        result["remote_cleanup"] = True
        result["sync_status"] = sync.status
        return result

    def restore_node(self, node_id: str) -> NodeSyncResult:
        """Return a withdrawn node to service after its settings were set up again."""

        def restore(state: AppState) -> None:
            node = self.find_node(state, node_id)
            node.management = MANAGEMENT_ACTIVE
            node.validate(path=f"nodes.{node_id}")

        self.state_updater(restore)
        return self.refresh(node_id)

    # ── existence ───────────────────────────────────────────────────────────

    def remove_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        """Delete the node from the VPS and then from the base."""
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node removal requires explicit confirmation")
        if self.uninstall_remote is None or self.forget_node_credentials is None:
            raise RuntimeError("node removal is unavailable")
        node = deepcopy(self.find_node(self.state_reader(), node_id))
        self.uninstall_remote(node)
        return self._remove_local_node(node, status="removed")

    def detach_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]:
        """Forget local publication only; an offline remote runtime is NOT stopped."""
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node detach requires explicit confirmation")
        if self.forget_node_credentials is None:
            raise RuntimeError("node credential cleanup is unavailable")
        node = deepcopy(self.find_node(self.state_reader(), node_id))
        result = self._remove_local_node(node, status="detached")
        result["remote_cleanup"] = False
        return result

    def _remove_local_node(self, node: NodeConfig, *, status: str) -> dict[str, object]:
        node_id = node.id

        def remove(state: AppState) -> None:
            current = self.find_node(state, node_id)
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

    @staticmethod
    def _same_removal_target(current: NodeConfig, expected: NodeConfig) -> bool:
        return (
            current.id == expected.id
            and current.address == expected.address
            and current.ssh_port == expected.ssh_port
            and current.ssh_user == expected.ssh_user
            and current.control_port == expected.control_port
            and current.control_fingerprint == expected.control_fingerprint
        )


__all__ = ["NodeLifecycle"]
