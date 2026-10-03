"""Injected runtime boundary for two-participant cascade transactions."""

from __future__ import annotations

from typing import Protocol

from hydra.contracts.managed_node_models import CascadeDefinition


class CascadeRuntime(Protocol):
    """Implementations must snapshot and query operation receipts before effects."""

    def capabilities(self, participant_id: str) -> dict[str, dict[str, bool]]: ...

    def ensure_snapshot(
        self,
        operation_id: str,
        participant_id: str,
        previous: CascadeDefinition | None,
    ) -> None: ...

    def participant_status(self, operation_id: str, participant_id: str) -> str: ...

    def prepare_participants(self, operation_id: str, definition: CascadeDefinition) -> None: ...

    def apply_participant(
        self,
        operation_id: str,
        participant_id: str,
        definition: CascadeDefinition | None,
    ) -> None: ...

    def verify_path(self, operation_id: str, definition: CascadeDefinition) -> bool: ...

    def commit_profiles(
        self,
        operation_id: str,
        definition: CascadeDefinition | None,
    ) -> None: ...

    def rollback_participant(self, operation_id: str, participant_id: str) -> bool: ...

    def finalize_participant(
        self, operation_id: str, participant_id: str, definition: CascadeDefinition | None
    ) -> bool: ...


__all__ = ["CascadeRuntime"]
