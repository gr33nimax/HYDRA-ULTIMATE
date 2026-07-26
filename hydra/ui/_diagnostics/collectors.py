"""Compatibility facade over cohesive diagnostic collector modules."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.ui import tui as _tui
from hydra.ui._diagnostics import censorship_checks as _censorship
from hydra.ui._diagnostics import network_checks as _network
from hydra.ui._diagnostics import performance_checks as _performance
from hydra.ui._diagnostics import system_checks as _system

DEFAULT_TIMEOUT = _system.DEFAULT_TIMEOUT
_thread_local = _system._thread_local
original_getaddrinfo = _system.original_getaddrinfo

DPI_BLOCKED_SITES = _censorship.DPI_BLOCKED_SITES
GEO_BLOCKED_SITES = _censorship.GEO_BLOCKED_SITES
GEOBLOCK_INSPECT_DOMAINS = _censorship.GEOBLOCK_INSPECT_DOMAINS
RKN_STUB_IPS = _censorship.RKN_STUB_IPS

for _name in (
    "clear", "title", "info", "success", "warn", "error", "menu", "prompt",
    "panel", "kv", "confirm", "_bytes_auto", "_bar", "_ok", "GREEN", "CYAN",
    "YELLOW", "RED", "BOLD", "DIM", "WHITE", "NC", "PANEL_W",
):
    globals()[_name] = getattr(_tui, _name)

_ROUTES = {
    "filtered_getaddrinfo": _system,
    "check_system_ipv6": _system,
    "ensure_packages": _system,
    "_command_argv": _system,
    "run_with_spinner": _system,
    "run_function_with_spinner": _system,
    "run_streaming_cmd": _system,
    "run_direct_cmd": _system,
    "make_http_request": _network,
    "get_ip_address": _network,
    "query_primary_geoip": _network,
    "check_custom_service": _network,
    "test_ip_region": _network,
    "check_domain_censor": _censorship,
    "run_censorcheck_python": _censorship,
    "classify_censor_status": _censorship,
    "is_port_listening": _censorship,
    "get_reality_sni": _censorship,
    "run_tspu_radar": _censorship,
    "test_censorcheck": _censorship,
    "test_iperf3_ru": _performance,
    "test_cpu_sysbench": _performance,
    "run_parallel_pings": _performance,
    "run_http_speed": _performance,
    "test_bench_speedtest": _performance,
}
_IMPLEMENTATIONS = {
    name: getattr(module, name)
    for name, module in _ROUTES.items()
}
_MODULES = tuple(dict.fromkeys(_ROUTES.values()))
_PATCHABLE_NAMES = (
    *_ROUTES,
    "DEFAULT_TIMEOUT",
    "_thread_local",
    "original_getaddrinfo",
    "DPI_BLOCKED_SITES",
    "GEO_BLOCKED_SITES",
    "GEOBLOCK_INSPECT_DOMAINS",
    "RKN_STUB_IPS",
    "clear",
    "title",
    "info",
    "success",
    "warn",
    "error",
    "menu",
    "prompt",
    "panel",
    "kv",
    "confirm",
    "_bytes_auto",
    "_bar",
    "_ok",
    "GREEN",
    "CYAN",
    "YELLOW",
    "RED",
    "BOLD",
    "DIM",
    "WHITE",
    "NC",
    "PANEL_W",
)


def _bind_dependencies() -> None:
    facade = globals()
    for module in _MODULES:
        for name in _PATCHABLE_NAMES:
            if name in facade and hasattr(module, name):
                setattr(module, name, facade[name])


def _delegate(name: str, *args, **kwargs):
    _bind_dependencies()
    return _IMPLEMENTATIONS[name](*args, **kwargs)


def filtered_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return _delegate("filtered_getaddrinfo", host, port, family, type, proto, flags)


def check_system_ipv6() -> bool:
    return _delegate("check_system_ipv6")


def ensure_packages(pkgs: list[str], app: ApplicationService) -> bool:
    return _delegate("ensure_packages", pkgs, app)


def _command_argv(cmd: str | list[str] | tuple[str, ...]) -> list[str]:
    return _delegate("_command_argv", cmd)


def run_with_spinner(title_text, cmd, app: ApplicationService):
    return _delegate("run_with_spinner", title_text, cmd, app)


def run_function_with_spinner(title_text, func, *args, **kwargs):
    return _delegate("run_function_with_spinner", title_text, func, *args, **kwargs)


def run_streaming_cmd(title_text, cmd, app: ApplicationService):
    return _delegate("run_streaming_cmd", title_text, cmd, app)


def run_direct_cmd(title_text, cmd, app: ApplicationService):
    return _delegate("run_direct_cmd", title_text, cmd, app)


def make_http_request(*args, **kwargs):
    return _delegate("make_http_request", *args, **kwargs)


def get_ip_address(version: int = 4) -> str:
    return _delegate("get_ip_address", version)


def query_primary_geoip(ip: str, service: str) -> str:
    return _delegate("query_primary_geoip", ip, service)


def check_custom_service(*args, **kwargs):
    return _delegate("check_custom_service", *args, **kwargs)


def test_ip_region():
    return _delegate("test_ip_region")


def check_domain_censor(*args, **kwargs):
    return _delegate("check_domain_censor", *args, **kwargs)


def run_censorcheck_python(mode: str) -> dict:
    return _delegate("run_censorcheck_python", mode)


def classify_censor_status(*args, **kwargs):
    return _delegate("classify_censor_status", *args, **kwargs)


def is_port_listening(port: int) -> bool:
    return _delegate("is_port_listening", port)


def get_reality_sni() -> str:
    return _delegate("get_reality_sni")


def run_tspu_radar(*args, **kwargs):
    return _delegate("run_tspu_radar", *args, **kwargs)


def test_censorcheck(mode: str):
    return _delegate("test_censorcheck", mode)


def test_iperf3_ru(app: ApplicationService):
    return _delegate("test_iperf3_ru", app)


def test_cpu_sysbench(app: ApplicationService):
    return _delegate("test_cpu_sysbench", app)


def run_parallel_pings(nodes, app: ApplicationService):
    return _delegate("run_parallel_pings", nodes, app)


def run_http_speed(url):
    return _delegate("run_http_speed", url)


def test_bench_speedtest(app: ApplicationService):
    return _delegate("test_bench_speedtest", app)
