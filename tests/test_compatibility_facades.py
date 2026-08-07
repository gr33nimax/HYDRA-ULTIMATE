from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

from hydra.plugins import defaults, registry
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.base import PluginStatus
from hydra.plugins.hysteria2.plugin import Hysteria2Plugin
from hydra.plugins.mieru.plugin import MieruPlugin
from hydra.plugins.naive.plugin import NaivePlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.ui import menus


ROOT = Path(__file__).parents[1]

LEGACY_MENU_EXPORTS = (
    "_awg_generate_wizard",
    "_awg_generate_wizard_menu",
    "_manage_awg_profiles",
    "_menu_anytls_obfuscation",
    "_menu_mieru_obfuscation",
    "_rotate_awg_obfuscation",
    "_tune_awg_hardware",
)

PLUGIN_CLASS_EXPORTS = (
    "AmneziaWGPlugin",
    "AntiDPIPlugin",
    "AnyTLSPlugin",
    "DNSCryptPlugin",
    "Fail2banPlugin",
    "HoneypotPlugin",
    "Hysteria2Plugin",
    "IPBanPlugin",
    "MieruPlugin",
    "NaivePlugin",
    "ShadowTLSPlugin",
    "SnellPlugin",
    "TelemtPlugin",
    "TrustTunnelPlugin",
    "WarpPlugin",
    "WdttPlugin",
)

PURE_COMMAND_HELPERS = (
    (AmneziaWGPlugin, "add_profile"),
    (AmneziaWGPlugin, "remove_profile"),
    (AnyTLSPlugin, "set_preset"),
    (Hysteria2Plugin, "set_domain"),
    (Hysteria2Plugin, "set_port"),
    (Hysteria2Plugin, "set_congestion"),
    (Hysteria2Plugin, "set_obfs_password"),
    (MieruPlugin, "set_preset"),
    (NaivePlugin, "set_domain"),
    (NaivePlugin, "set_transport"),
    (ShadowTLSPlugin, "set_handshake_sni"),
    (SnellPlugin, "set_settings"),
    (TrustTunnelPlugin, "set_transport"),
)


def test_legacy_menu_helpers_remain_importable_from_the_facade():
    assert all(callable(getattr(menus, name, None)) for name in LEGACY_MENU_EXPORTS)


@pytest.mark.parametrize(
    ("helper_name", "binder_name"),
    (
        ("_select_user", "_user_menus"),
        ("_show_user_detail", "_user_menus"),
        ("_show_connections", "_monitoring_menus"),
        ("_install_admin_bot", "_telegram_menus"),
        ("_show_plugin_clients", "_extended_protocol_menus"),
        ("_apply_error_text", "_extended_protocol_menus"),
        ("_manage_awg_profiles", "_extended_protocol_menus"),
    ),
)
def test_menu_facade_forwards_legacy_helper_patches(helper_name, binder_name):
    original = getattr(menus, helper_name)

    def replacement(*_args, **_kwargs):
        return None

    binder = getattr(menus, binder_name)
    setattr(menus, helper_name, replacement)
    try:
        assert getattr(binder(), helper_name) is replacement
    finally:
        setattr(menus, helper_name, original)
        binder()


def test_registry_reexports_historical_plugin_classes_and_status():
    for name in PLUGIN_CLASS_EXPORTS:
        assert getattr(registry, name) is getattr(defaults, name)
        assert name in registry.__all__
    assert registry.PluginStatus is PluginStatus
    assert "PluginStatus" in registry.__all__


@pytest.mark.parametrize(
    ("legacy_module", "canonical_module", "exports"),
    (
        (
            "hydra.ui.network_info",
            "hydra.services.network_info",
            ("NetworkSnapshot", "is_private_ip", "snapshot", "start"),
        ),
        (
            "hydra.plugins.tls_support",
            "hydra.utils.tls",
            ("resolve_tls_material",),
        ),
        (
            "hydra.plugins.config",
            "hydra.contracts",
            (
                "ConfigFragment",
                "ConfigurationError",
                "FragmentValidationError",
                "PluginConfig",
            ),
        ),
    ),
)
def test_dependency_migration_facades_are_thin_and_exact(
    legacy_module,
    canonical_module,
    exports,
):
    legacy = importlib.import_module(legacy_module)
    canonical = importlib.import_module(canonical_module)
    source_path = Path(inspect.getsourcefile(legacy))
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    assert len(source_path.read_text(encoding="utf-8").splitlines()) < 40
    assert not any(
        isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        )
        for node in tree.body
    )
    for name in exports:
        assert getattr(legacy, name) is getattr(canonical, name)
        assert name in legacy.__all__


@pytest.mark.parametrize(("plugin_type", "method_name"), PURE_COMMAND_HELPERS)
def test_plugin_commands_do_not_own_persistence_or_runtime_apply(
    plugin_type,
    method_name,
):
    parameters = inspect.signature(
        getattr(plugin_type, method_name),
    ).parameters
    assert "state" in parameters
    assert "apply_configuration" not in parameters


def test_plugin_helpers_do_not_resolve_the_application_boundary_themselves():
    forbidden = {
        "hydra.core.orchestrator",
        "hydra.plugins.management",
        "hydra.services.application",
    }
    paths = {
        ROOT / inspect.getsourcefile(plugin_type)
        for plugin_type, _method_name in PURE_COMMAND_HELPERS
    }
    paths.add(ROOT / "hydra" / "plugins" / "context.py")
    violations: list[str] = []
    for path in sorted(paths):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules = {node.module or ""}
                if node.module == "hydra.core":
                    modules.update(
                        "hydra.core.orchestrator"
                        for alias in node.names
                        if alias.name == "orchestrator"
                    )
            else:
                continue
            for module in modules & forbidden:
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno} {module}")
    assert violations == []
