"""Transactional phases for applying the desired SNI-router runtime."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.core.sni_router_runtime_models import (
    RuntimeBackup,
    RuntimeOperations,
    RuntimeSettings,
)
from hydra.core.state_models import AppState


@dataclass(frozen=True)
class ValidationOutcome:
    """Result of validating a pending Caddy configuration."""

    valid: bool
    upgraded_binary: bool
    detail: str


def _restore_config(path: Path, previous: bytes | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    rollback = path.with_suffix(".json.rollback")
    rollback.write_bytes(previous)
    rollback.replace(path)


def _apply_loopback_firewall(
    backends: list[dict],
    quic_owner: str | None,
    settings: RuntimeSettings,
    host: Any,
) -> None:
    try:
        ports = [
            (
                str(backend["port"]),
                backend["name"] == quic_owner,
            )
            for backend in backends
        ]
        decoy_ports = {
            int(port)
            for port in settings.decoy_ports.values()
        }
        decoy_ports.update(
            int(backend["decoy_port"])
            for backend in backends
            if backend.get("decoy_port")
        )
        ports.extend((str(port), False) for port in sorted(decoy_ports))
        dynamic_ports = {
            int(value)
            for backend in backends
            if backend.get("route_kind") == "http_path_proxy"
            for value in (backend["port"], backend["decoy_port"])
        }
        for port, include_udp in ports:
            protocols = ("tcp", "udp") if include_udp else ("tcp",)
            for protocol in protocols:
                rule = [
                    "INPUT",
                    "-p",
                    protocol,
                    "--dport",
                    port,
                    "!",
                    "-i",
                    "lo",
                    "-j",
                    "DROP",
                ]
                if int(port) in dynamic_ports:
                    rule[-2:-2] = [
                        "-m",
                        "comment",
                        "--comment",
                        "hydra-caddy-dynamic-loopback",
                    ]
                host.run(
                    ["iptables", "-D", *rule],
                    capture_output=True,
                )
                host.run(
                    ["iptables", "-I", "INPUT", "1", *rule[1:]],
                    capture_output=True,
                )
    except Exception:
        pass


def _restore_routing_units(
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
    backup: RuntimeBackup,
) -> None:
    from hydra.core import source_transparency

    operations.restore_unit_file(settings.caddy_service_file, backup.caddy_unit)
    operations.restore_unit_file(
        settings.source_service_file,
        backup.source_unit,
    )
    operations.restore_unit_file(
        settings.relay_service_file,
        backup.relay_unit,
    )
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    if backup.source_transparency:
        host.run(
            ["systemctl", "restart", settings.source_service_name],
            capture_output=True,
        )
    else:
        operations.remove_source_service()
        source_transparency.clear()
    if backup.relay_unit is None:
        operations.remove_relay_service()
    else:
        host.run(
            ["systemctl", "restart", settings.relay_service_name],
            capture_output=True,
        )


def _ensure_decoy_sites(backends: list[dict]) -> None:
    from hydra.core.decoy import ensure_decoy_site, ensure_site

    for backend in backends:
        if backend["name"] in ("sub_server", "shadowtls"):
            continue
        if backend.get("route_kind") == "http_path_proxy":
            ensure_site(
                Path(str(backend["decoy_root"])),
                str(backend["decoy_theme"]),
            )
            continue
        try:
            ensure_decoy_site(backend["name"])
        except Exception as exc:
            print(f"  Error generating decoy for {backend['name']}: {exc}")


def _write_pending_config(
    state: AppState,
    backends: list[dict],
    settings: RuntimeSettings,
    operations: RuntimeOperations,
) -> Path:
    config = operations.generate_config(backends, state)
    settings.caddy_config_dir.mkdir(parents=True, exist_ok=True)
    settings.caddy_log_dir.mkdir(parents=True, exist_ok=True)
    pending = settings.caddy_config.with_suffix(".json.pending")
    pending.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return pending


def _validate_pending(
    state: AppState,
    pending: Path,
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
) -> ValidationOutcome:
    command = [
        str(settings.caddy_binary),
        "validate",
        "--config",
        str(pending),
    ]
    result = host.run(command, capture_output=True, text=True)
    upgraded = False
    output = f"{result.stderr}\n{result.stdout}"
    if result.returncode != 0 and "local_address" in output:
        print("  Updating Caddy L4 for source-address preservation...")
        upgraded = operations.install(state=state, force=True)
        if upgraded:
            result = host.run(command, capture_output=True, text=True)
    detail = str(result.stderr or result.stdout or "")
    return ValidationOutcome(result.returncode == 0, upgraded, detail)


def _read_optional(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def _capture_backup(
    settings: RuntimeSettings,
    operations: RuntimeOperations,
) -> RuntimeBackup:
    config = _read_optional(settings.caddy_config)
    source_transparency = False
    if config is not None:
        try:
            source_transparency = operations.has_source_preservation(
                json.loads(config),
            )
        except (TypeError, ValueError):
            pass
    return RuntimeBackup(
        config=config,
        caddy_unit=_read_optional(settings.caddy_service_file),
        source_unit=_read_optional(settings.source_service_file),
        relay_unit=_read_optional(settings.relay_service_file),
        source_transparency=source_transparency,
    )


def _apply_routing(
    state: AppState,
    backends: list[dict],
    quic_owner: str | None,
    operations: RuntimeOperations,
) -> None:
    from hydra.core import source_transparency

    tcp_ports, udp_ports = operations.source_ports(backends, quic_owner)
    relay_routes = operations.relay_routes(backends, state)
    udp_relay_routes = operations.udp_relay_routes(backends, state)
    if tcp_ports or udp_ports:
        source_transparency.apply(tcp_ports, udp_ports)
        operations.install_source_service(tcp_ports, udp_ports)
    else:
        operations.remove_source_service()
        source_transparency.clear()
    if relay_routes or udp_relay_routes:
        operations.install_relay_service(relay_routes, udp_relay_routes)
    else:
        operations.remove_relay_service()
    if not operations.install_caddy_service(
        source_required=bool(tcp_ports or udp_ports),
        relay_required=bool(relay_routes or udp_relay_routes),
    ):
        raise RuntimeError("cannot install Caddy L4 systemd unit")


def _switch_public_udp(
    quic_owner: str | None,
    had_quic_proxy: bool,
) -> None:
    if quic_owner:
        from hydra.utils.firewall import open_udp

        open_udp(443, "udp-quic-mux")
    elif had_quic_proxy:
        from hydra.utils.firewall import close_udp

        close_udp(443, "udp-quic-mux")


def _activate_service(
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
) -> bool:
    host.run(
        ["systemctl", "enable", settings.caddy_service_name],
        capture_output=True,
    )
    result = host.run(
        ["systemctl", "reload-or-restart", settings.caddy_service_name],
        capture_output=True,
    )
    if result.returncode != 0:
        result = host.run(
            ["systemctl", "restart", settings.caddy_service_name],
            capture_output=True,
        )
    return result.returncode == 0 and operations.is_active()


def _rollback_runtime(
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
    backup: RuntimeBackup,
    *,
    upgraded_binary: bool,
) -> None:
    try:
        _restore_config(settings.caddy_config, backup.config)
        host.run(
            ["systemctl", "restart", settings.caddy_service_name],
            capture_output=True,
        )
    finally:
        _restore_routing_units(settings, host, operations, backup)
        if upgraded_binary:
            operations.restore_binary()
        if backup.config is not None:
            host.run(
                ["systemctl", "restart", settings.caddy_service_name],
                capture_output=True,
            )


def rebuild(
    state: AppState,
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
) -> bool:
    """Render, validate, and transactionally apply the desired SNI runtime."""
    quic_owner = operations.get_quic_owner(state)
    had_quic_proxy = operations.config_had_quic_proxy()
    backends = operations.collect_backends(state)
    if not operations.needs_mux(state):
        if had_quic_proxy and not quic_owner:
            _switch_public_udp(quic_owner, had_quic_proxy)
        operations.stop()
        return True
    if not operations.is_installed() and not operations.install(state=state):
        return False

    _ensure_decoy_sites(backends)
    pending = _write_pending_config(state, backends, settings, operations)
    validation = _validate_pending(state, pending, settings, host, operations)
    if not validation.valid:
        if validation.upgraded_binary:
            operations.restore_binary()
        pending.unlink(missing_ok=True)
        print(f"  Caddy L4 config validation error: {validation.detail}")
        return False

    backup = _capture_backup(settings, operations)
    try:
        _apply_routing(state, backends, quic_owner, operations)
    except Exception as exc:
        if validation.upgraded_binary:
            operations.restore_binary()
        _restore_routing_units(settings, host, operations, backup)
        pending.unlink(missing_ok=True)
        print(f"  Caddy source-preservation routing error: {exc}")
        return False

    pending.replace(settings.caddy_config)
    _apply_loopback_firewall(backends, quic_owner, settings, host)
    _switch_public_udp(quic_owner, had_quic_proxy)
    if _activate_service(settings, host, operations):
        return True
    _rollback_runtime(
        settings,
        host,
        operations,
        backup,
        upgraded_binary=validation.upgraded_binary,
    )
    return False


__all__ = ["rebuild"]
