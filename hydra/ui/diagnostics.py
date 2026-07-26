"""Compatibility facade for decomposed diagnostic UI layers."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.services.diagnostic_compatibility import (
    compatibility_dependency,
    operations_from_application,
)
from hydra.services.diagnostics import diagnostic_scope
from hydra.ui import tui as _tui
from hydra.ui._diagnostics import collectors as _collectors
from hydra.ui._diagnostics import render as _render
from hydra.ui._diagnostics import report as _report

DEFAULT_TIMEOUT = _collectors.DEFAULT_TIMEOUT
_thread_local = _collectors._thread_local
original_getaddrinfo = _collectors.original_getaddrinfo

DPI_BLOCKED_SITES = _collectors.DPI_BLOCKED_SITES
GEO_BLOCKED_SITES = _collectors.GEO_BLOCKED_SITES
GEOBLOCK_INSPECT_DOMAINS = _collectors.GEOBLOCK_INSPECT_DOMAINS
RKN_STUB_IPS = _collectors.RKN_STUB_IPS

for _name in (
    "clear", "title", "info", "success", "warn", "error", "menu", "prompt",
    "panel", "kv", "confirm", "_bytes_auto", "_bar", "_ok", "GREEN", "CYAN",
    "YELLOW", "RED", "BOLD", "DIM", "WHITE", "NC", "PANEL_W",
):
    globals()[_name] = getattr(_tui, _name)


def _application(app: ApplicationService | None = None) -> ApplicationService:
    if app is None:
        raise ValueError("ApplicationService must be injected into diagnostics")
    return app


_COLLECTOR_NAMES = (
    "filtered_getaddrinfo",
    "check_system_ipv6",
    "ensure_packages",
    "_command_argv",
    "run_with_spinner",
    "run_function_with_spinner",
    "run_streaming_cmd",
    "run_direct_cmd",
    "make_http_request",
    "get_ip_address",
    "query_primary_geoip",
    "check_custom_service",
    "check_domain_censor",
    "run_censorcheck_python",
    "classify_censor_status",
    "test_ip_region",
    "is_port_listening",
    "get_reality_sni",
    "run_tspu_radar",
    "test_censorcheck",
    "test_iperf3_ru",
    "test_cpu_sysbench",
    "run_parallel_pings",
    "run_http_speed",
    "test_bench_speedtest",
)
_COLLECTOR_IMPLS = {
    name: getattr(_collectors, name)
    for name in _COLLECTOR_NAMES
}
_APP_COLLECTORS = {
    "ensure_packages",
    "run_with_spinner",
    "run_streaming_cmd",
    "run_direct_cmd",
    "test_iperf3_ru",
    "test_cpu_sysbench",
    "run_parallel_pings",
    "test_bench_speedtest",
}


def _bind_collectors() -> None:
    facade = globals()
    for name in _COLLECTOR_NAMES:
        setattr(_collectors, name, facade[name])
    for name in (
        "DEFAULT_TIMEOUT", "original_getaddrinfo", "clear", "title", "info",
        "success", "warn", "error", "menu", "prompt", "panel", "kv",
        "confirm", "_bytes_auto", "_bar", "_ok", "GREEN", "CYAN", "YELLOW",
        "RED", "BOLD", "DIM", "WHITE", "NC", "PANEL_W",
        "DPI_BLOCKED_SITES", "GEO_BLOCKED_SITES",
        "GEOBLOCK_INSPECT_DOMAINS", "RKN_STUB_IPS",
    ):
        setattr(_collectors, name, facade[name])


def _call_collector(
    name: str,
    *args,
    app: ApplicationService | None = None,
    **kwargs,
):
    _bind_collectors()
    implementation = _COLLECTOR_IMPLS[name]
    if name in _APP_COLLECTORS:
        application = _application(app)
        with diagnostic_scope(operations_from_application(application)):
            return implementation(*args, application, **kwargs)
    return implementation(*args, **kwargs)


def filtered_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return _call_collector(
        "filtered_getaddrinfo", host, port, family, type, proto, flags,
    )


def check_system_ipv6() -> bool:
    return _call_collector("check_system_ipv6")


def ensure_packages(
    pkgs: list[str],
    app: ApplicationService | None = None,
) -> bool:
    return _call_collector("ensure_packages", pkgs, app=app)


def _command_argv(cmd):
    return _call_collector("_command_argv", cmd)


def run_with_spinner(title_text, cmd, app: ApplicationService | None = None):
    return _call_collector("run_with_spinner", title_text, cmd, app=app)


def run_function_with_spinner(title_text, func, *args, **kwargs):
    return _call_collector(
        "run_function_with_spinner", title_text, func, *args, **kwargs,
    )


def run_streaming_cmd(title_text, cmd, app: ApplicationService | None = None):
    return _call_collector("run_streaming_cmd", title_text, cmd, app=app)


def run_direct_cmd(title_text, cmd, app: ApplicationService | None = None):
    return _call_collector("run_direct_cmd", title_text, cmd, app=app)


def make_http_request(*args, **kwargs):
    return _call_collector("make_http_request", *args, **kwargs)


def get_ip_address(version: int = 4) -> str:
    return _call_collector("get_ip_address", version)


def query_primary_geoip(ip: str, service: str) -> str:
    return _call_collector("query_primary_geoip", ip, service)


def check_custom_service(*args, **kwargs):
    return _call_collector("check_custom_service", *args, **kwargs)


def check_domain_censor(*args, **kwargs):
    return _call_collector("check_domain_censor", *args, **kwargs)


def run_censorcheck_python(mode: str) -> dict:
    return _call_collector("run_censorcheck_python", mode)


def classify_censor_status(*args, **kwargs):
    return _call_collector("classify_censor_status", *args, **kwargs)


def test_ip_region():
    return _call_collector("test_ip_region")


def is_port_listening(port: int) -> bool:
    return _call_collector("is_port_listening", port)


def get_reality_sni() -> str:
    return _call_collector("get_reality_sni")


def run_tspu_radar(*args, **kwargs):
    return _call_collector("run_tspu_radar", *args, **kwargs)


def test_censorcheck(mode: str):
    return _call_collector("test_censorcheck", mode)


def test_iperf3_ru(app: ApplicationService | None = None):
    return _call_collector("test_iperf3_ru", app=app)


def test_cpu_sysbench(app: ApplicationService | None = None):
    return _call_collector("test_cpu_sysbench", app=app)


def run_parallel_pings(nodes, app: ApplicationService | None = None):
    return _call_collector("run_parallel_pings", nodes, app=app)


def run_http_speed(url):
    return _call_collector("run_http_speed", url)


def test_bench_speedtest(app: ApplicationService | None = None):
    return _call_collector("test_bench_speedtest", app=app)


def run_diagnostics_report(
    app: ApplicationService | None = None,
) -> str:
    application = _application(app)
    with diagnostic_scope(operations_from_application(application)):
        return _report.run_diagnostics_report(application)


_RENDER_IMPLS = {
    "show_live_report": _render.show_live_report,
    "menu_diagnostics": _render.menu_diagnostics,
}


def _bind_render() -> None:
    facade = globals()
    for name in (
        "clear", "title", "error", "kv", "menu", "panel", "prompt",
        "run_function_with_spinner", "run_diagnostics_report",
        "test_bench_speedtest", "test_censorcheck", "test_cpu_sysbench",
        "test_ip_region", "test_iperf3_ru", "test_generate_report",
    ):
        setattr(_render, name, facade[name])


def show_live_report(app: ApplicationService | None = None):
    _bind_render()
    application = _application(app)
    with diagnostic_scope(operations_from_application(application)):
        return _RENDER_IMPLS["show_live_report"](application)


test_generate_report = show_live_report


def menu_diagnostics(
    state,
    app: ApplicationService | None = None,
):
    _bind_render()
    application = _application(app)
    with diagnostic_scope(operations_from_application(application)):
        return _RENDER_IMPLS["menu_diagnostics"](state, application)


def __getattr__(name: str):
    """Resolve historical monkeypatch modules from the infrastructure adapter."""

    if name in {"os", "shutil", "socket", "subprocess", "time", "urllib"}:
        return compatibility_dependency(name)
    raise AttributeError(name)
