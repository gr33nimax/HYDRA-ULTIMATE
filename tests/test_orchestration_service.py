"""Instance-scoped orchestration contracts."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
from types import SimpleNamespace

from hydra.contracts import ConfigFragment
from hydra.core.state import AppState, PluginState, get_protocol
from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus
from hydra.plugins.container import PluginContainer
from hydra.services.orchestration_service import OrchestrationService


ROOT = Path(__file__).parents[1]


class LocalPlugin(BasePlugin):
    meta = PluginMeta(name="local", description="local test plugin")

    def __init__(self) -> None:
        self.enabled = 0

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self, state=None) -> PluginStatus:
        return PluginStatus(True, bool(self.enabled), bool(self.enabled))

    def configure(self, state) -> ConfigFragment:
        return ConfigFragment()

    def on_enable(self, state) -> None:
        self.enabled += 1


def _service(tmp_path: Path) -> tuple[OrchestrationService, LocalPlugin]:
    plugin = LocalPlugin()
    host = SimpleNamespace(which=lambda _name: None)
    plugins = PluginContainer([plugin], host=host)
    service = OrchestrationService(
        plugins=plugins,
        singbox=SimpleNamespace(log=lambda *_args: None),
        nft=SimpleNamespace(),
        host=host,
        save_state=lambda _state: None,
        get_protocol=get_protocol,
        certificates=SimpleNamespace(ensure=lambda *_args: ("cert", "key")),
        traffic_daemon_service=tmp_path / "traffic.service",
        apply_journal=tmp_path / "apply.jsonl",
        apply_lock_file=tmp_path / "apply.lock",
    )
    return service, plugin


def test_plugin_lifecycle_uses_the_service_owned_container(tmp_path):
    service, plugin = _service(tmp_path)
    state = AppState(
        protocols={"local": PluginState(installed=True)},
    )
    service.apply_config = lambda _state: True

    assert service.enable(state, "local") is True
    assert state.protocols["local"].enabled is True
    assert plugin.enabled == 1


def test_failed_tls_activation_restores_domain_but_keeps_new_install(tmp_path):
    service, plugin = _service(tmp_path)
    plugin.meta = PluginMeta(
        name="local",
        description="local TLS test plugin",
        tls_domain_source="protocol",
    )
    saved: list[AppState] = []
    service.save_state = lambda current: saved.append(copy.deepcopy(current))
    service.certificates = SimpleNamespace(
        ensure=lambda *_args: (_ for _ in ()).throw(
            RuntimeError("certificate failed"),
        ),
    )
    service.apply_config = lambda _state: True
    state = AppState(protocols={"local": PluginState()})

    try:
        service.activate_plugin(
            state,
            "local",
            domain="vpn.example.com",
        )
        assert False, "certificate failure must be reported"
    except RuntimeError as exc:
        assert str(exc) == "certificate failed"

    assert state.protocols["local"].installed is True
    assert state.protocols["local"].enabled is False
    assert "domain" not in state.protocols["local"].config
    assert "domain" not in saved[-1].protocols["local"].config


def test_successful_tls_activation_commits_staged_domain(tmp_path):
    service, plugin = _service(tmp_path)
    plugin.meta = PluginMeta(
        name="local",
        description="local TLS test plugin",
        tls_domain_source="protocol",
    )
    service.apply_config = lambda _state: True
    state = AppState(protocols={"local": PluginState()})

    assert service.activate_plugin(
        state,
        "local",
        domain="VPN.Example.COM.",
    )

    assert state.protocols["local"].installed is True
    assert state.protocols["local"].enabled is True
    assert state.protocols["local"].config["domain"] == "vpn.example.com"


def test_failed_network_domain_activation_restores_previous_domain(tmp_path):
    service, plugin = _service(tmp_path)
    plugin.meta = PluginMeta(
        name="local",
        description="local network TLS test plugin",
        tls_domain_source="network",
    )
    service.certificates = SimpleNamespace(
        ensure=lambda *_args: (_ for _ in ()).throw(
            RuntimeError("certificate failed"),
        ),
    )
    service.apply_config = lambda _state: True
    state = AppState(protocols={"local": PluginState()})
    state.network.domain = "old.example.com"

    try:
        service.activate_plugin(
            state,
            "local",
            domain="new.example.com",
        )
        assert False, "certificate failure must be reported"
    except RuntimeError:
        pass

    assert state.network.domain == "old.example.com"
    assert state.protocols["local"].installed is True
    assert state.protocols["local"].enabled is False


def test_instance_orchestrator_does_not_import_global_registry():
    path = ROOT / "hydra" / "services" / "orchestration_service.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    assert "hydra.plugins.registry" not in modules
