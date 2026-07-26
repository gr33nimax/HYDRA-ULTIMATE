"""Architecture guards for the decomposed diagnostic collectors."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from hydra.ui._diagnostics import censorship_checks
from hydra.ui._diagnostics import collectors
from hydra.ui._diagnostics import network_checks
from hydra.ui._diagnostics import performance_checks
from hydra.ui._diagnostics import system_checks


ROOT = Path(__file__).parents[1]
DIAGNOSTICS = ROOT / "hydra" / "ui" / "_diagnostics"
ROLE_MODULES = {
    "system_checks": system_checks,
    "network_checks": network_checks,
    "censorship_checks": censorship_checks,
    "performance_checks": performance_checks,
}
SUPPORT_MODULES = {
    "censorship_radar",
    "network_region_data",
    "network_service_exchanges",
    "report_sections",
}
EXPECTED_OWNERS = {
    "system_checks": {
        "filtered_getaddrinfo",
        "check_system_ipv6",
        "ensure_packages",
        "_command_argv",
        "run_with_spinner",
        "run_function_with_spinner",
        "run_streaming_cmd",
        "run_direct_cmd",
    },
    "network_checks": {
        "make_http_request",
        "get_ip_address",
        "query_primary_geoip",
        "check_custom_service",
        "test_ip_region",
    },
    "censorship_checks": {
        "check_domain_censor",
        "run_censorcheck_python",
        "classify_censor_status",
        "is_port_listening",
        "get_reality_sni",
        "run_tspu_radar",
        "test_censorcheck",
    },
    "performance_checks": {
        "test_iperf3_ru",
        "test_cpu_sysbench",
        "run_parallel_pings",
        "run_http_speed",
        "test_bench_speedtest",
    },
}


def _tree(name: str) -> ast.Module:
    path = DIAGNOSTICS / f"{name}.py"
    return ast.parse(path.read_text(encoding="utf-8"))


def test_collector_layers_stay_within_size_budgets() -> None:
    facade_lines = (DIAGNOSTICS / "collectors.py").read_text(
        encoding="utf-8",
    ).splitlines()
    assert len(facade_lines) < 250

    for path in DIAGNOSTICS.glob("*.py"):
        if path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        assert len(lines) <= 500, f"{path.name} grew to {len(lines)} lines"
        functions = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        assert all(
            node.end_lineno - node.lineno + 1 <= 120
            for node in functions
        ), path.name


def test_every_extracted_collector_is_routed_without_orphans() -> None:
    expected_routes: dict[str, str] = {}
    for owner, expected_functions in EXPECTED_OWNERS.items():
        definitions = {
            node.name
            for node in _tree(owner).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert definitions == expected_functions
        expected_routes.update(
            {function_name: owner for function_name in expected_functions}
        )

    actual_routes = {
        name: module.__name__.rsplit(".", 1)[-1]
        for name, module in collectors._ROUTES.items()
    }
    assert actual_routes == expected_routes

    for name, owner in expected_routes.items():
        assert collectors._IMPLEMENTATIONS[name].__module__ == (
            f"hydra.ui._diagnostics.{owner}"
        )


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("_command_argv", ("echo ok",)),
        ("query_primary_geoip", ("203.0.113.2", "RIPE")),
        ("classify_censor_status", (200, 200)),
        ("run_http_speed", ("https://example.com/file",)),
    ],
)
def test_facade_delegates_to_each_cohesive_module(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    args: tuple[object, ...],
) -> None:
    calls: list[tuple[object, ...]] = []
    sentinel = object()

    def implementation(*received):
        calls.append(received)
        return sentinel

    monkeypatch.setitem(collectors._IMPLEMENTATIONS, name, implementation)
    assert getattr(collectors, name)(*args) is sentinel
    assert calls == [args]


def test_extracted_collectors_do_not_bypass_the_application_port() -> None:
    forbidden_imports = {
        "hydra.core.host",
        "hydra.core.singbox",
        "hydra.core.systemd",
        "hydra.utils.firewall",
    }
    forbidden_facades = {
        "hydra.ui.diagnostics",
        "hydra.ui._diagnostics.collectors",
    }

    for name in (*ROLE_MODULES, *SUPPORT_MODULES, "collectors"):
        tree = _tree(name)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(
                    f"{node.module}.{alias.name}"
                    for alias in node.names
                )
            elif isinstance(node, ast.Name):
                assert node.id != "production_application"

        assert imported.isdisjoint(forbidden_imports)
        if name != "collectors":
            assert imported.isdisjoint(forbidden_facades)


def test_diagnostic_support_modules_only_point_downward() -> None:
    forbidden_by_module = {
        "network_region_data": {
            "hydra.ui._diagnostics.network_checks",
            "hydra.ui._diagnostics.collectors",
            "hydra.ui.diagnostics",
        },
        "network_service_exchanges": {
            "hydra.ui._diagnostics.network_checks",
            "hydra.ui._diagnostics.collectors",
            "hydra.ui.diagnostics",
        },
        "censorship_radar": {
            "hydra.ui._diagnostics.censorship_checks",
            "hydra.ui._diagnostics.collectors",
            "hydra.ui.diagnostics",
        },
        "report_sections": {
            "hydra.ui._diagnostics.report",
            "hydra.ui.diagnostics",
        },
    }
    for name, forbidden in forbidden_by_module.items():
        imported: set[str] = set()
        for node in ast.walk(_tree(name)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(
                    f"{node.module}.{alias.name}"
                    for alias in node.names
                )
        assert imported.isdisjoint(forbidden), name


def test_support_modules_are_owned_by_stable_facades() -> None:
    expected = {
        "network_checks": {
            "hydra.ui._diagnostics.network_region_data",
            "hydra.ui._diagnostics.network_service_exchanges",
        },
        "censorship_checks": {
            "hydra.ui._diagnostics.censorship_radar",
        },
        "report": {
            "hydra.ui._diagnostics.report_sections",
        },
    }
    for owner, required in expected.items():
        imported: set[str] = set()
        for node in ast.walk(_tree(owner)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(
                    f"{node.module}.{alias.name}"
                    for alias in node.names
                )
        assert required <= imported, owner


def test_host_actions_keep_an_explicit_application_parameter() -> None:
    expected = {
        "system_checks": {
            "ensure_packages",
            "run_with_spinner",
            "run_streaming_cmd",
            "run_direct_cmd",
        },
        "performance_checks": {
            "test_iperf3_ru",
            "test_cpu_sysbench",
            "run_parallel_pings",
            "test_bench_speedtest",
        },
    }

    for owner, function_names in expected.items():
        functions = {
            node.name: node
            for node in _tree(owner).body
            if isinstance(node, ast.FunctionDef)
        }
        for function_name in function_names:
            node = functions[function_name]
            positional = node.args.posonlyargs + node.args.args
            app_index = next(
                index for index, arg in enumerate(positional) if arg.arg == "app"
            )
            first_default = len(positional) - len(node.args.defaults)
            assert app_index < first_default
