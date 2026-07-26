"""Architecture contracts for Fail2ban and Honeypot plugins."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from hydra.plugins.fail2ban.plugin import Fail2banPlugin
from hydra.plugins.honeypot.plugin import HoneypotPlugin


ROOT = Path(__file__).parents[1] / "hydra" / "plugins"
PACKAGES = {
    "fail2ban": {
        "configuration.py",
        "model.py",
        "observation.py",
        "plugin.py",
        "runtime.py",
    },
    "honeypot": {
        "configuration.py",
        "model.py",
        "observation.py",
        "plugin.py",
        "runtime.py",
    },
}


def _tree(package: str, filename: str) -> ast.Module:
    return ast.parse(
        (ROOT / package / filename).read_text(encoding="utf-8"),
    )


def _local_imports(package: str, filename: str) -> set[str]:
    prefix = f"hydra.plugins.{package}"
    result = set()
    for node in ast.walk(_tree(package, filename)):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.module == prefix:
            result.update(alias.name for alias in node.names)
        elif node.module.startswith(f"{prefix}."):
            result.add(node.module.rsplit(".", 1)[-1])
    return result


def test_security_plugin_modules_and_functions_stay_bounded() -> None:
    for package, filenames in PACKAGES.items():
        for filename in filenames:
            source = (ROOT / package / filename).read_text(encoding="utf-8")
            assert len(source.splitlines()) <= 350, (
                package,
                filename,
            )
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    size = node.end_lineno - node.lineno + 1
                    assert size <= 120, (
                        package,
                        filename,
                        node.name,
                        size,
                    )


def test_security_plugin_companions_do_not_import_facades_backwards() -> None:
    for package, filenames in PACKAGES.items():
        for filename in filenames - {"plugin.py"}:
            assert "plugin" not in _local_imports(package, filename), (
                package,
                filename,
            )


def test_security_plugin_internal_graphs_are_acyclic() -> None:
    for package, filenames in PACKAGES.items():
        graph = {
            filename.removesuffix(".py"): {
                target
                for target in _local_imports(package, filename)
                if f"{target}.py" in filenames
            }
            for filename in filenames
        }
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise AssertionError(f"{package} cycle through {node}")
            if node in visited:
                return
            visiting.add(node)
            for target in graph.get(node, set()):
                visit(target)
            visiting.remove(node)
            visited.add(node)

        for node in graph:
            visit(node)


def test_security_plugins_do_not_access_application_state_storage() -> None:
    forbidden = {
        "hydra.core.state",
        "hydra.core.state_store",
        "hydra.core.state_storage",
    }
    violations = []
    for package, filenames in PACKAGES.items():
        for filename in filenames:
            for node in ast.walk(_tree(package, filename)):
                if isinstance(node, ast.ImportFrom) and node.module in forbidden:
                    violations.append((package, filename, node.module))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in forbidden:
                            violations.append(
                                (package, filename, alias.name),
                            )
    assert violations == []


def test_fail2ban_keeps_historical_method_surface_and_signatures() -> None:
    expected = {
        "clear_logs": [],
        "install": ["self"],
        "uninstall": ["self"],
        "_filters": [],
        "jail_options": ["self", "state"],
        "set_jail_options": [
            "self",
            "state",
            "jail",
            "bantime",
            "findtime",
            "maxretry",
        ],
        "set_jail_enabled": ["self", "state", "jail", "enabled"],
        "add_whitelist": ["self", "state", "network"],
        "remove_whitelist": ["self", "state", "network"],
        "reset_jails": ["self", "state"],
        "_valid_whitelist": ["state"],
        "_write_jails": ["self", "state"],
        "_remove_owned_configuration": [],
        "_installed": ["self"],
        "_awg_dynamic_debug_control": [],
        "_cleanup_legacy_awg_debug": ["self"],
        "_remove_legacy_portscan_rule": [],
        "configure": ["self", "state"],
        "restore_defaults": ["self", "state"],
        "apply": ["self", "state"],
        "snapshot": ["self", "state"],
        "rollback": ["self", "state", "snapshot"],
        "status": ["self", "state"],
        "recent_logs": ["self", "limit"],
        "traffic": ["self", "state"],
        "on_enable": ["self", "state"],
        "on_disable": ["self", "state"],
    }
    for name, parameters in expected.items():
        assert list(
            inspect.signature(getattr(Fail2banPlugin, name)).parameters,
        ) == parameters


def test_honeypot_keeps_historical_method_surface_and_signatures() -> None:
    expected = {
        "install": ["self"],
        "uninstall": ["self"],
        "configure": ["self", "state"],
        "snapshot": ["self", "state"],
        "rollback": ["self", "state", "snapshot"],
        "apply": ["self", "state"],
        "_service_diagnostics": ["self"],
        "_wait_until_stably_running": ["self"],
        "status": ["self", "state"],
        "_normalize_whitelist": ["values"],
        "_sync_host_whitelist": ["self", "config", "state"],
        "_write_script": ["self", "port", "whitelist"],
        "_install_service": ["self", "port", "whitelist"],
        "_remove_service": ["self", "close_port"],
        "unban": ["self", "raw"],
        "management_snapshot": ["self"],
        "recent_logs": ["self", "limit"],
        "set_port": ["self", "state", "port"],
        "add_whitelist": ["self", "state", "network"],
        "remove_whitelist": ["self", "state", "network"],
        "unban_address": ["self", "state", "address"],
        "_unban_ip": ["self", "ip"],
        "_load_state": ["self"],
        "banned_addresses": ["self"],
        "_save_state": ["self", "data"],
        "traffic": ["self", "state"],
        "on_enable": ["self", "state"],
        "on_disable": ["self", "state"],
    }
    for name, parameters in expected.items():
        assert list(
            inspect.signature(getattr(HoneypotPlugin, name)).parameters,
        ) == parameters
