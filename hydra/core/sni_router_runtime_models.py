"""Runtime dependency model for SNI-router reconciliation."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from hydra.core.state_models import AppState


@dataclass(frozen=True)
class RuntimeSettings:
    """Mutable host artifacts owned by the SNI-router runtime."""

    caddy_binary: Path
    caddy_config: Path
    caddy_config_dir: Path
    caddy_log_dir: Path
    caddy_service_name: str
    caddy_service_file: Path
    source_service_name: str
    source_service_file: Path
    relay_service_name: str
    relay_service_file: Path
    internal_ports: Mapping[str, int]
    decoy_ports: Mapping[str, int]


@dataclass(frozen=True)
class RuntimeOperations:
    """Patchable policy, rendering, installation, and unit-management seams."""

    get_quic_owner: Callable[[AppState], str | None]
    config_had_quic_proxy: Callable[[], bool]
    collect_backends: Callable[[AppState], list[dict]]
    needs_mux: Callable[[AppState], bool]
    stop: Callable[[], None]
    is_installed: Callable[[], bool]
    install: Callable[..., bool]
    generate_config: Callable[[list[dict], AppState], dict]
    has_source_preservation: Callable[[object], bool]
    restore_binary: Callable[[], bool]
    source_ports: Callable[
        [list[dict], str | None],
        tuple[set[int], set[int]],
    ]
    relay_routes: Callable[[list[dict], AppState], list[tuple[str, int, int]]]
    udp_relay_routes: Callable[
        [list[dict], AppState],
        list[tuple[str, int, int]],
    ]
    install_source_service: Callable[[set[int], set[int]], None]
    remove_source_service: Callable[[], None]
    install_relay_service: Callable[
        [list[tuple[str, int, int]], list[tuple[str, int, int]]],
        None,
    ]
    remove_relay_service: Callable[[], None]
    install_caddy_service: Callable[..., bool]
    restore_unit_file: Callable[[Path, bytes | None], None]
    is_active: Callable[[], bool]


@dataclass(frozen=True)
class RuntimeBackup:
    """Host artifacts captured before a transactional runtime change."""

    config: bytes | None
    caddy_unit: bytes | None
    source_unit: bytes | None
    relay_unit: bytes | None
    source_transparency: bool


__all__ = ["RuntimeBackup", "RuntimeOperations", "RuntimeSettings"]
