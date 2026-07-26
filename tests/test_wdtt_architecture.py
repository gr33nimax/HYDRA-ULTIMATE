"""Architecture contract for the decomposed WDTT plugin."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from hydra.plugins.base import BasePlugin
from hydra.plugins.wdtt.plugin import WdttPlugin


ROOT = Path(__file__).parents[1] / "hydra" / "plugins" / "wdtt"
MODULES = {
    "build.py",
    "configuration.py",
    "lifecycle.py",
    "model.py",
    "observation.py",
    "plugin.py",
}
COMPANIONS = MODULES - {"plugin.py"}


def _tree(filename: str) -> ast.Module:
    return ast.parse((ROOT / filename).read_text(encoding="utf-8"))


def _local_imports(filename: str) -> set[str]:
    result = set()
    for node in ast.walk(_tree(filename)):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.module == "hydra.plugins.wdtt":
            result.update(alias.name for alias in node.names)
        elif node.module.startswith("hydra.plugins.wdtt."):
            result.add(node.module.rsplit(".", 1)[-1])
    return result


def test_wdtt_modules_and_functions_stay_bounded() -> None:
    for filename in MODULES:
        source = (ROOT / filename).read_text(encoding="utf-8")
        limit = 260 if filename == "plugin.py" else 500
        assert len(source.splitlines()) <= limit, filename
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                size = node.end_lineno - node.lineno + 1
                assert size <= 160, f"{filename}:{node.name} ({size})"


def test_wdtt_companions_do_not_import_the_facade_backwards() -> None:
    for filename in COMPANIONS:
        assert "plugin" not in _local_imports(filename), filename


def test_wdtt_internal_module_graph_is_acyclic() -> None:
    graph = {
        filename.removesuffix(".py"): {
            target
            for target in _local_imports(filename)
            if f"{target}.py" in MODULES
        }
        for filename in MODULES
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise AssertionError(f"WDTT dependency cycle through {node}")
        if node in visited:
            return
        visiting.add(node)
        for target in graph.get(node, set()):
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def test_wdtt_plugin_keeps_historical_method_surface() -> None:
    expected = {
        "_add_masquerade",
        "_build_wdtt_server",
        "_check_go",
        "_derive_password",
        "_ensure_go",
        "_fw_close_udp",
        "_fw_open_udp",
        "_fw_tool",
        "_go_arch",
        "_go_env",
        "_go_installed_version",
        "_go_required_version",
        "_install_go_toolchain",
        "_install_service",
        "_installed",
        "_ipt_persist",
        "_masquerade_exists",
        "_remove_masquerade",
        "_ver_tuple",
        "aggregate_traffic_snapshot",
        "apply",
        "client_link",
        "configure",
        "connected_clients",
        "generate_client_config",
        "hot_reload",
        "install",
        "observe_runtime",
        "on_disable",
        "on_enable",
        "on_user_add",
        "on_user_block",
        "on_user_remove",
        "password_registry",
        "public_server_ip",
        "save_client_link",
        "save_password_registry",
        "status",
        "total_traffic",
        "traffic",
        "uninstall",
    }
    assert all(callable(getattr(WdttPlugin, name)) for name in expected)


def test_wdtt_plugin_keeps_historical_signatures() -> None:
    expected = {
        "observe_runtime": ["self"],
        "password_registry": [],
        "save_password_registry": ["data"],
        "hot_reload": [],
        "public_server_ip": [],
        "save_client_link": ["link", "filename"],
        "install": ["self"],
        "uninstall": ["self"],
        "configure": ["self", "state"],
        "apply": ["self", "state"],
        "status": ["self", "state"],
        "traffic": ["self", "state"],
        "total_traffic": ["self", "state"],
        "aggregate_traffic_snapshot": ["self", "state"],
        "connected_clients": ["self", "state"],
        "_install_service": [
            "dtls_port",
            "wg_port",
            "main_password",
            "admin_id",
            "bot_token",
        ],
        "_ipt_persist": ["self"],
        "_build_wdtt_server": ["self"],
        "_install_go_toolchain": ["self", "required"],
    }
    for name, parameters in expected.items():
        assert list(inspect.signature(getattr(WdttPlugin, name)).parameters) == (
            parameters
        )


def test_wdtt_preserves_generic_and_aggregate_traffic_hooks() -> None:
    assert WdttPlugin.traffic_snapshot is BasePlugin.traffic_snapshot
    assert WdttPlugin.ingest_traffic is BasePlugin.ingest_traffic
    assert (
        WdttPlugin.aggregate_traffic_snapshot
        is not BasePlugin.aggregate_traffic_snapshot
    )
