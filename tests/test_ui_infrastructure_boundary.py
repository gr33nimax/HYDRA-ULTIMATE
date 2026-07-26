"""Architecture guards for the bounded administration UI."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
UI_ROOT = ROOT / "hydra" / "ui"
UI_BOUNDARY = (
    ROOT / "hydra" / "ui" / "_menus" / "users.py",
    ROOT / "hydra" / "ui" / "_menus" / "telegram.py",
    ROOT / "hydra" / "ui" / "_menus" / "monitoring.py",
    ROOT / "hydra" / "ui" / "_diagnostics" / "collectors.py",
    ROOT / "hydra" / "ui" / "_diagnostics" / "report.py",
    ROOT / "hydra" / "ui" / "_diagnostics" / "render.py",
)
UI_INFRASTRUCTURE_EXCEPTIONS = {
    UI_ROOT / "tui.py": (
        "the terminal adapter owns console dimensions, environment styling, "
        "and non-blocking keyboard input"
    ),
}
PRODUCTION_UI = tuple(
    path
    for path in sorted(UI_ROOT.rglob("*.py"))
    if path not in UI_INFRASTRUCTURE_EXCEPTIONS
)


def test_admin_ui_does_not_import_privileged_infrastructure() -> None:
    forbidden_modules = {
        "hydra.core.host",
        "hydra.core.systemd",
        "hydra.core.singbox",
        "hydra.utils.firewall",
    }
    forbidden_stdlib_roots = {
        "http",
        "os",
        "pathlib",
        "psutil",
        "requests",
        "select",
        "shutil",
        "socket",
        "ssl",
        "subprocess",
        "tempfile",
        "time",
        "urllib",
    }
    forbidden_state_names = {"save_state", "update_state"}
    violations: list[str] = []

    for path in PRODUCTION_UI:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if (
                        alias.name in forbidden_modules
                        or root in forbidden_stdlib_roots
                        or "_infrastructure" in alias.name
                    ):
                        violations.append(
                            f"{path.relative_to(ROOT)}:{node.lineno} {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                names = {alias.name for alias in node.names}
                module = node.module or ""
                root = module.split(".", 1)[0]
                if (
                    module in forbidden_modules
                    or root in forbidden_stdlib_roots
                    or "_infrastructure" in module
                    or any("_infrastructure" in name for name in names)
                ):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} {module}"
                    )
                if module == "hydra.core" and names & {"singbox"}:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} hydra.core.singbox"
                    )
                if module == "hydra.core.state" and names & forbidden_state_names:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} "
                        f"{sorted(names & forbidden_state_names)}"
                    )
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"
            ):
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno} open()",
                )
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("/proc/")
            ):
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno} {node.value}",
                )

    assert violations == [], (
        "UI bypassed application service ports: " + ", ".join(violations)
    )


def test_terminal_adapter_is_the_only_documented_ui_io_exception() -> None:
    assert UI_INFRASTRUCTURE_EXCEPTIONS == {
        ROOT / "hydra" / "ui" / "tui.py": (
            "the terminal adapter owns console dimensions, environment styling, "
            "and non-blocking keyboard input"
        ),
    }


def test_neutral_monitoring_ports_do_not_import_host_adapters() -> None:
    port_modules = (
        ROOT / "hydra" / "services" / "diagnostics.py",
        ROOT / "hydra" / "services" / "system_monitoring.py",
    )
    violations: list[str] = []
    for path in port_modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if "_infrastructure" in module or "_compatibility" in module:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} {module}",
                    )

    assert violations == [], (
        "neutral service port imported an outer adapter: "
        + ", ".join(violations)
    )


def test_extracted_admin_ui_requires_an_injected_application() -> None:
    violations: list[str] = []
    for path in UI_BOUNDARY:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "production_application":
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert violations == []


def test_ui_does_not_use_the_process_global_plugin_invoker() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "hydra" / "ui").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "DEFAULT_INVOKER":
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and node.module == "hydra.plugins.invoker":
                imported = {alias.name for alias in node.names}
                if "DEFAULT_INVOKER" in imported:
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert violations == []


def test_diagnostics_is_a_thin_compatibility_facade() -> None:
    facade = ROOT / "hydra" / "ui" / "diagnostics.py"
    assert len(facade.read_text(encoding="utf-8").splitlines()) < 300
    for name in ("collectors.py", "report.py", "render.py"):
        assert (ROOT / "hydra" / "ui" / "_diagnostics" / name).is_file()


def test_diagnostics_public_exports_remain_available() -> None:
    from hydra.ui import diagnostics

    expected = {
        "check_system_ipv6",
        "ensure_packages",
        "run_with_spinner",
        "run_function_with_spinner",
        "make_http_request",
        "get_ip_address",
        "query_primary_geoip",
        "check_custom_service",
        "check_domain_censor",
        "run_censorcheck_python",
        "test_ip_region",
        "test_censorcheck",
        "test_iperf3_ru",
        "test_cpu_sysbench",
        "test_bench_speedtest",
        "run_diagnostics_report",
        "show_live_report",
        "test_generate_report",
        "menu_diagnostics",
    }
    assert expected <= set(vars(diagnostics))
