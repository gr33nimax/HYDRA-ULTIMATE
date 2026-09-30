"""Application-facing port for managed-node operations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.observation import NodeObservation
from hydra.services.nodes.reconciler import NodeSyncResult


class NodeManagementOperations(Protocol):
    def add_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
    ) -> NodeSyncResult: ...

    def resume_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
    ) -> NodeSyncResult: ...

    def remove_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]: ...

    def detach_node(self, node_id: str, *, confirmed: bool) -> dict[str, object]: ...

    def import_vk_cookies(self, node_id: str, source_path: str) -> None: ...

    def list_nodes(self, state: AppState) -> list[NodeConfig]: ...

    def observations(self) -> dict[str, NodeObservation]: ...

    def resolve_revision(self, branch: str) -> str: ...

    def published_export(self, state: AppState, node_id: str) -> NodeClientExport | None: ...

    def traffic_reports(self) -> tuple[NodeTrafficReport, ...]: ...

    def collect_traffic(self) -> None: ...

    def reconcile_all(self) -> dict[str, dict[str, object]]: ...

    def check(self, node_id: str) -> dict[str, object]: ...

    def refresh(self, node_id: str, *, force: bool = False) -> NodeSyncResult: ...

    def change_name(self, node_id: str, name: str, *, region: str | None = None) -> NodeConfig: ...

    def change_profile_name(self, node_id: str, key: str, name: str) -> None: ...

    def change_update_target(self, node_id: str, *, branch: str, revision: str) -> None: ...

    def change_protocol(self, node_id: str, name: str, spec: NodeProtocolSpec) -> NodeSyncResult: ...

    def update(self, node_id: str) -> dict[str, object]: ...


class UnavailableNodeOperations:
    """Fail closed when an adapter is assembled without production node services."""

    def __getattr__(self, name: str):
        raise RuntimeError("node management is unavailable")


__all__ = ["NodeManagementOperations", "UnavailableNodeOperations"]
