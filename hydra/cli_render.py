"""Human-oriented rendering for the HYDRA command line adapter."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.cli_format import (
    BOLD as _BOLD,
    DIM as _DIM,
    GREEN as _GREEN,
    RED as _RED,
    generic_lines as _generic_lines,
    mark as _mark,
    paint as _paint,
    scalar as _scalar,
    section as _section,
    table as _table,
)
from hydra.cli_render_calls import (
    render_calls_telemetry,
    render_calls_telemetry_record,
)


COMMAND_TITLES = {
    "status": "HYDRA status",
    "check": "Configuration check",
    "apply": "Configuration apply",
    "backup.create": "Backup creation",
    "backup.inspect": "Backup inspection",
    "backup.restore": "Backup restore",
    "upgrade.check": "Upgrade readiness",
    "upgrade.migrate-state": "State migration",
    "kernel.status": "Kernel status",
    "kernel.switch": "Kernel switch",
    "user.list": "Users",
    "user.show": "User details",
    "user.add": "Add user",
    "user.ensure-default": "Default user",
    "user.rename": "Rename user",
    "user.set-device-limit": "Update device limit",
    "user.rotate-hydrabox-key": "Rotate HydraBox JWE key",
    "user.block": "Block user",
    "user.unblock": "Unblock user",
    "user.remove": "Remove user",
    "plugin.list": "Plugins",
    "plugin.show": "Plugin details",
    "plugin.status": "Plugin status",
    "plugin.health": "Plugin health",
    "plugin.install": "Plugin installation",
    "plugin.reinstall": "Plugin reinstallation",
    "plugin.enable": "Enable plugin",
    "plugin.disable": "Disable plugin",
    "plugin.uninstall": "Plugin removal",
    "plugin.command": "Plugin command",
    "plugin.query": "Plugin query",
    "plugin.action": "Plugin action",
    "uninstall": "HYDRA uninstall",
    "antidpi.selftest": "AntiDPI self-test",
    "antidpi.capture": "AntiDPI capture",
    "antidpi.sync": "AntiDPI synchronization",
    "calls.telemetry.start": "Hydra VK Tunnel telemetry",
    "calls.telemetry.status": "Hydra VK Tunnel telemetry status",
    "calls.telemetry.report": "Hydra VK Tunnel telemetry report",
    "calls.telemetry.tail": "Hydra VK Tunnel live telemetry",
    "calls.telemetry.mark": "Mark Hydra VK Tunnel telemetry",
    "calls.telemetry.export": "Export Hydra VK Tunnel telemetry",
    "calls.telemetry.stop": "Stop Hydra VK Tunnel telemetry",
    "version": "HYDRA version",
}

def _status_state(status: Mapping[str, object]) -> str:
    if status.get("installed") is False:
        return "not installed"
    if status.get("running"):
        return "running"
    if status.get("enabled"):
        return "stopped"
    return "disabled"


def _plugin_is_relevant(status: Mapping[str, object]) -> bool:
    return bool(
        status.get("enabled")
        or status.get("installed")
        or status.get("running")
        or status.get("error")
        or status.get("drift") not in {None, "", "none", "in_sync"}
    )


def _network_lines(network: Mapping[str, object]) -> list[str]:
    domain = network.get("domain") or "not configured"
    lines = [f"  Domain: {domain}"]
    if network.get("sub_domain"):
        lines.append(f"  Subscription domain: {network['sub_domain']}")
    if network.get("server_ip"):
        lines.append(f"  Server IP: {network['server_ip']}")
    if network.get("dns_servers"):
        lines.append(f"  DNS servers: {_scalar(network['dns_servers'])}")
    tproxy = (
        f"enabled on port {network.get('tproxy_port', '-')}"
        if network.get("tproxy_enabled")
        else "disabled"
    )
    lines.append(f"  TPROXY: {tproxy}")
    dnscrypt = (
        f"running on port {network.get('dnscrypt_port', '-')}"
        if network.get("dnscrypt_enabled")
        else "disabled"
    )
    lines.append(f"  DNSCrypt: {dnscrypt}")
    clash = (
        f"enabled on port {network.get('clash_api_port', '-')}"
        if network.get("clash_api_enabled")
        else "disabled"
    )
    lines.append(f"  Clash API: {clash}")
    return lines


def _render_status(payload: Mapping[str, object], *, color: bool) -> list[str]:
    users = int(payload.get("users", 0) or 0)
    lines = [
        (
            f"State schema v{_scalar(payload.get('version'))}"
            f"  |  {users} user{'s' if users != 1 else ''}"
        ),
    ]
    network = payload.get("network")
    if isinstance(network, Mapping) and network:
        _section(lines, "Network", color=color)
        lines.extend(_network_lines(network))

    plugins = payload.get("plugins")
    if isinstance(plugins, Mapping):
        _section(lines, "Plugins", color=color)
        runtime = payload.get("runtime")
        runtime_map = runtime if isinstance(runtime, Mapping) else {}
        rows: list[tuple[object, ...]] = []
        hidden = 0
        for name, raw_status in sorted(plugins.items()):
            status = raw_status if isinstance(raw_status, Mapping) else {}
            if not _plugin_is_relevant(status):
                hidden += 1
                continue
            runtime_status = runtime_map.get(name, {})
            if not isinstance(runtime_status, Mapping):
                runtime_status = {}
            drift = status.get("drift") or runtime_status.get("drift") or "none"
            rows.append(
                (
                    name,
                    _status_state(status),
                    drift,
                ),
            )
        lines.extend(_table(("Name", "State", "Drift"), rows))
        if hidden:
            lines.append(
                f"  {hidden} inactive plugin{'s' if hidden != 1 else ''} "
                "hidden; run: hydra plugin list",
            )

    tls_mux = payload.get("tls_mux")
    if isinstance(tls_mux, Mapping):
        _section(lines, "TLS multiplexer", color=color)
        required = bool(tls_mux.get("required"))
        if not required:
            lines.append("  not required")
        else:
            lines.append(
                "  "
                + (
                    _paint("[ok] healthy", _GREEN, color=color)
                    if tls_mux.get("ok")
                    else _paint("[fail] requires attention", _RED, color=color)
                ),
            )
    return lines


def _render_check(payload: Mapping[str, object], *, color: bool) -> list[str]:
    ok = bool(payload.get("ok"))
    lines = [
        _paint(
            "[ok] Preflight passed" if ok else "[fail] Preflight failed",
            _GREEN if ok else _RED,
            color=color,
        ),
    ]
    configuration = payload.get("configuration")
    if isinstance(configuration, Mapping):
        schema = configuration.get("schema_version", "-")
        revision = configuration.get("revision")
        detail = f"schema v{schema}"
        if revision is not None:
            detail += f", revision {revision}"
        lines.append(f"Configuration: {_mark(configuration.get('valid'))} {detail}")

    host = payload.get("host")
    if isinstance(host, Mapping):
        _section(lines, "Host checks", color=color)
        checks = host.get("checks")
        if isinstance(checks, Sequence):
            rows = []
            for raw_check in checks:
                if not isinstance(raw_check, Mapping):
                    continue
                rows.append(
                    (
                        _mark(raw_check.get("ok")),
                        raw_check.get("name", "unknown"),
                        raw_check.get("detail", ""),
                    ),
                )
            lines.extend(_table(("State", "Check", "Detail"), rows))
        failures = host.get("required_failures", [])
        warnings = host.get("warnings", [])
        if failures:
            lines.append(f"  Required failures: {_scalar(failures)}")
        if warnings:
            lines.append(f"  Warnings: {_scalar(warnings)}")

    changes = payload.get("changes")
    if isinstance(changes, Mapping):
        _section(lines, "Pending changes", color=color)
        summary = changes.get("changes")
        if isinstance(summary, Mapping):
            lines.extend(_generic_lines(summary, indent=2))
        plugins = changes.get("plugins")
        if plugins:
            lines.append(f"  Plugins: {_scalar(plugins)}")
        conflicts = changes.get("conflicts")
        if conflicts:
            lines.append(
                _paint(
                    f"  Conflicts: {_scalar(conflicts)}",
                    _RED,
                    color=color,
                ),
            )
        reconciliation = changes.get("reconciliation")
        if isinstance(reconciliation, Sequence) and reconciliation:
            rows = []
            for raw_action in reconciliation:
                if not isinstance(raw_action, Mapping):
                    continue
                rows.append(
                    (
                        raw_action.get("plugin", "-"),
                        raw_action.get("operation", "-"),
                        raw_action.get("reason", raw_action.get("drift", "-")),
                    ),
                )
            lines.extend(_table(("Plugin", "Action", "Reason"), rows))
        tls_mux = changes.get("tls_mux")
        if isinstance(tls_mux, Mapping) and tls_mux.get("required"):
            lines.append(
                f"  TLS multiplexer: {_mark(tls_mux.get('ok'))} "
                f"{'healthy' if tls_mux.get('ok') else 'requires attention'}",
            )
        if (
            not summary
            and not plugins
            and not conflicts
            and not reconciliation
        ):
            lines.append("  none")
    if ok:
        lines.extend(["", _paint("Ready: sudo hydra apply", _DIM, color=color)])
    return lines


def _render_users(payload: Mapping[str, object]) -> list[str]:
    users = payload.get("users")
    if not isinstance(users, Sequence):
        return _generic_lines(payload, skip=frozenset({"ok"}))
    rows = []
    for raw_user in users:
        if not isinstance(raw_user, Mapping):
            continue
        registered = int(raw_user.get("devices_registered", 0) or 0)
        limit = int(raw_user.get("device_limit", 0) or 0)
        devices = (
            f"{registered}/{limit}"
            if limit
            else f"{registered}/unlimited"
        )
        rows.append(
            (
                raw_user.get("email", "-"),
                "blocked" if raw_user.get("blocked") else "active",
                devices,
                _scalar(raw_user.get("protocols", [])),
            ),
        )
    return _table(("User", "State", "Devices", "Protocols"), rows)


def _render_plugins(payload: Mapping[str, object]) -> list[str]:
    plugins = payload.get("plugins")
    if not isinstance(plugins, Sequence):
        return _generic_lines(payload, skip=frozenset({"ok"}))
    rows = []
    for raw_plugin in plugins:
        if not isinstance(raw_plugin, Mapping):
            continue
        status = raw_plugin.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        rows.append(
            (
                raw_plugin.get("name", "-"),
                raw_plugin.get("category", "-"),
                _status_state(status_map),
                _mark(status_map.get("healthy")),
            ),
        )
    return _table(("Name", "Category", "State", "Health"), rows)


def _render_error(payload: Mapping[str, object], *, color: bool) -> str:
    details = payload.get("error_details")
    detail_map = details if isinstance(details, Mapping) else {}
    lines = [
        _paint("Command failed", _BOLD + _RED, color=color),
        str(payload.get("error") or detail_map.get("message") or "unknown error"),
    ]
    code = detail_map.get("code")
    if code:
        lines.append(f"Code: {code}")
    usage = detail_map.get("usage")
    if usage:
        lines.extend(["", _paint("Usage", _BOLD, color=color), f"  {usage}"])
    return "\n".join(lines)


def render_human(
    command_id: str,
    payload: object,
    *,
    color: bool,
) -> str:
    """Render any public CLI result without exposing raw JSON structure."""
    if command_id == "error":
        mapping = payload if isinstance(payload, Mapping) else {"error": payload}
        return _render_error(mapping, color=color)

    title = COMMAND_TITLES.get(command_id, "HYDRA result")
    lines = [_paint(title, _BOLD, color=color), ""]
    mapping = payload if isinstance(payload, Mapping) else {"result": payload}
    if command_id == "status":
        lines.extend(_render_status(mapping, color=color))
    elif command_id == "check":
        lines.extend(_render_check(mapping, color=color))
    elif command_id == "user.list":
        lines.extend(_render_users(mapping))
    elif command_id == "plugin.list":
        lines.extend(_render_plugins(mapping))
    elif command_id.startswith("calls.telemetry."):
        lines.extend(render_calls_telemetry(mapping))
    elif command_id == "version":
        lines.append(_scalar(mapping.get("version")))
    else:
        ok = mapping.get("ok")
        if ok is True:
            lines.append(_paint("[ok] Completed", _GREEN, color=color))
        elif ok is False:
            lines.append(_paint("[fail] Failed", _RED, color=color))
            error = mapping.get("error")
            details = mapping.get("error_details")
            detail_map = details if isinstance(details, Mapping) else {}
            if isinstance(error, Mapping):
                message = error.get("message")
            else:
                message = error
            message = message or detail_map.get("message")
            if message:
                lines.append(str(message))
            if detail_map.get("code"):
                lines.append(f"Code: {detail_map['code']}")
        lines.extend(
            _generic_lines(
                mapping,
                skip=frozenset({"ok", "error", "error_details"}),
            ),
        )
    return "\n".join(lines).rstrip()


__all__ = ["COMMAND_TITLES", "render_calls_telemetry_record", "render_human"]
