"""Architecture and runtime-only guards for TrustTunnel and ShadowTLS."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import hydra.core.singbox as singbox
import hydra.core.state as state_storage
import hydra.plugins.shadowtls.plugin as shadowtls_facade
import hydra.plugins.trusttunnel.plugin as trusttunnel_facade
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    ROOT / "hydra" / "plugins" / "trusttunnel",
    ROOT / "hydra" / "plugins" / "shadowtls",
)


def _production_modules() -> list[Path]:
    return [
        path
        for package in PACKAGES
        for path in package.glob("*.py")
    ]


def test_transport_modules_and_functions_remain_reviewable() -> None:
    oversized_modules = []
    oversized_functions = []
    for path in _production_modules():
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        if len(lines) > 350:
            oversized_modules.append(f"{path.name}={len(lines)}")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            length = (
                (node.end_lineno or node.lineno)
                - node.lineno
                + 1
            )
            if length > 120:
                oversized_functions.append(
                    f"{path.name}:{node.name}={length}"
                )
    assert oversized_modules == []
    assert oversized_functions == []


def test_transport_packages_do_not_import_persistence_or_facades() -> None:
    violations = []
    for path in _production_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module == "hydra.core.state":
                    violations.append(
                        f"{path.name}:{node.lineno} persistence"
                    )
                if (
                    path.name != "plugin.py"
                    and module.rsplit(".", 1)[-1] == "plugin"
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} facade"
                    )
    assert violations == []


def test_facades_keep_protocol_and_private_compatibility_seams() -> None:
    trust_expected = {
        "configure",
        "generate_client_config",
        "client_link",
        "client_links",
        "status",
        "connected_clients",
        "validate_config",
        "health",
        "set_transport",
        "_build_tcp_inbound",
        "_build_quic_inbound",
        "_build_client_outbound",
        "_transport",
        "_split_endpoint",
        "_collect_ss_clients",
        "_resolve_certs",
    }
    shadow_expected = {
        "configure",
        "generate_client_config",
        "client_link",
        "status",
        "connected_clients",
        "set_handshake_sni",
        "_validate_handshake_sni",
        "_probe_handshake_sni",
        "_server_ip",
        "_url_host",
        "_remove_iptables_rules",
        "_add_iptables_rules",
        "_get_total_traffic",
    }
    assert trust_expected <= set(vars(TrustTunnelPlugin))
    assert shadow_expected <= set(vars(ShadowTLSPlugin))


def test_status_without_state_is_runtime_only(monkeypatch) -> None:
    def fail_persistence():
        raise AssertionError("plugin attempted persistence I/O")

    monkeypatch.setattr(state_storage, "load_state", fail_persistence)
    monkeypatch.setattr(singbox, "is_installed", lambda: True)
    monkeypatch.setattr(singbox, "is_running", lambda: True)

    trust = TrustTunnelPlugin().status()
    shadow = ShadowTLSPlugin().status()

    for result in (trust, shadow):
        assert result.installed is True
        assert result.enabled is False
        assert result.running is False
        assert result.port == 443
        assert result.info == {}


def test_status_uses_explicit_state_access(monkeypatch) -> None:
    monkeypatch.setattr(singbox, "is_installed", lambda: True)
    monkeypatch.setattr(singbox, "is_running", lambda: True)
    trust_state = AppState(
        protocols={
            "trusttunnel": PluginState(
                enabled=True,
                config={
                    "domain": "tt.example.com",
                    "transport": "tcp",
                },
            )
        }
    )
    shadow_state = AppState(
        protocols={
            "shadowtls": PluginState(
                enabled=True,
                config={"handshake_sni": "www.google.com"},
            )
        }
    )
    trust_plugin = TrustTunnelPlugin()
    shadow_plugin = ShadowTLSPlugin()
    monkeypatch.setattr(
        trust_plugin,
        "health",
        lambda _state: {"ok": True, "errors": []},
    )
    monkeypatch.setattr(
        trust_plugin,
        "_get_total_traffic",
        lambda _state: 1024,
    )
    monkeypatch.setattr(
        shadow_plugin,
        "_get_total_traffic",
        lambda: 1024,
    )

    trust = trust_plugin.status(trust_state)
    shadow = shadow_plugin.status(shadow_state)

    for result in (trust, shadow):
        assert result.enabled is True
        assert result.running is True
        assert result.info["Общий трафик"] == "1.00 KB"


class _TrustRuntimeHost:
    def run(self, command, **_kwargs):
        if command[:2] == ["ss", "-t"]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "ESTAB 0 0 127.0.0.1:443 "
                    "198.51.100.7:54321\n"
                ),
            )
        raise AssertionError(command)


class _ShadowRuntimeHost:
    def run(self, command, **_kwargs):
        if command[:2] == ["ss", "-t"]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "ESTAB 0 127.0.0.1:443 "
                    "198.51.100.8:54321\n"
                ),
            )
        if command[0] == "iptables":
            return SimpleNamespace(returncode=0, stdout="")
        raise AssertionError(command)


def test_connected_clients_without_state_is_runtime_only(
    monkeypatch,
) -> None:
    def fail_persistence():
        raise AssertionError("plugin attempted persistence I/O")

    monkeypatch.setattr(state_storage, "load_state", fail_persistence)
    monkeypatch.setattr(
        trusttunnel_facade.shutil,
        "which",
        lambda _name: "/usr/bin/ss",
    )
    monkeypatch.setattr(
        shadowtls_facade.shutil,
        "which",
        lambda _name: "/usr/bin/ss",
    )
    monkeypatch.setattr(
        trusttunnel_facade,
        "HOST",
        _TrustRuntimeHost(),
    )
    monkeypatch.setattr(
        shadowtls_facade,
        "HOST",
        _ShadowRuntimeHost(),
    )

    trust = TrustTunnelPlugin().connected_clients()
    shadow = ShadowTLSPlugin().connected_clients()

    assert trust[0]["email"] == (
        "198.51.100.7 (TCP, 1 Conns)"
    )
    assert shadow[0]["email"] == "198.51.100.8 (1 TCP)"
