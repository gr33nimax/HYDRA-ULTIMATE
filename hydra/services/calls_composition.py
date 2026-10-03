"""Assemble the Calls subgraph for the canonical production composition root."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.services.calls import CallsService
from hydra.services.calls_health import CallsProbeStore
from hydra.services.calls_infrastructure import (
    CALLS_CREATOR_UNIT,
    CALLS_POOL_DIR,
    CALLS_POOL_STATE,
    CALLS_PROBE_STATE,
    CallsInfrastructure,
)
from hydra.services.creator_lock_infrastructure import CreatorFileLock
from hydra.services.creator_sessions import CreatorSessionManager
from hydra.services.headless_creator_infrastructure import HeadlessCreatorInfrastructure
from hydra.services.vk_turn_probe import VkTurnProbe


def create_calls_runtimes(
    host: HostBackend,
) -> tuple[HeadlessCreatorInfrastructure, CallsInfrastructure]:
    """Build Calls-owned runtime adapters with the supplied host boundary."""
    creator = HeadlessCreatorInfrastructure(
        host,
        pool_dir=CALLS_POOL_DIR,
        pool_state_file=CALLS_POOL_STATE,
        creator_unit=CALLS_CREATOR_UNIT,
        managed_consumer="calls",
        managed_unit_prefix="hydra-headless-creator-vk-calls",
    )
    runtime = CallsInfrastructure(host, pool_source=creator)
    return creator, runtime


def create_calls_service(
    host: HostBackend,
    creator_runtime: HeadlessCreatorInfrastructure,
    calls_runtime: CallsInfrastructure,
    protocols,
    orchestration,
    save_state: Callable[[AppState], None],
) -> CallsService:
    """Bind Calls use-cases to the current app's protocols and apply path."""
    creator = CreatorSessionManager({"vk": creator_runtime})
    lock_path = Path(
        os.environ.get("HYDRA_CALLS_LOCK_FILE", "/run/lock/hydra-calls.lock"),
    )
    return CallsService(
        runtime=calls_runtime,
        creator=creator,
        protocols=protocols,
        save_state=save_state,
        apply_config=orchestration.apply_config,
        operation_lock=CreatorFileLock(host, lock_path),
        last_apply_error=orchestration.last_apply_error,
        probe_store=CallsProbeStore(host, CALLS_PROBE_STATE),
        turn_probe=VkTurnProbe(),
    )


__all__ = ["create_calls_runtimes", "create_calls_service"]
