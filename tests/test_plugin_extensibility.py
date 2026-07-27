"""Proof that a plugin descriptor drives cross-cutting application features."""
from __future__ import annotations

import ast
from pathlib import Path

from hydra.bootstrap import production_application
from hydra.contracts import BackupResource, ConfigFragment
from hydra.core import singbox_config
from hydra.core.state import AppState, PluginState
from hydra.plugins.base import (
    BasePlugin,
    MaintenanceTask,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.container import PluginContainer
from hydra.plugins.defaults import default_plugins
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_commands import PluginCommandService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.services.protocols import ProtocolService
from hydra.services.sync_ports import default_sync_operations


ROOT = Path(__file__).parents[1]


class ExtensionPlugin(BasePlugin):
    meta = PluginMeta(
        name="extension",
        description="test extension",
        display_name="Extension Transport",
        commands=("set_mode",),
        queries=("read_mode", "refresh_due"),
        actions=("refresh", "rotate"),
        tls_domain_source="protocol",
        config_defaults=(("mode", "safe"),),
        maintenance_tasks=(
            MaintenanceTask(
                action="refresh",
                due_query="refresh_due",
                enabled_flag="sync_extension_enabled",
                title="Refresh extension data",
                apply_on_success=True,
            ),
        ),
        backup_resources=(
            BackupResource("/etc/extension/config.toml", "file"),
        ),
    )

    def __init__(self) -> None:
        self.rotations = 0

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self, state=None) -> PluginStatus:
        return PluginStatus(True, True, True)

    def configure(self, state) -> ConfigFragment:
        port = state.protocols.get(
            "extension",
            PluginState(),
        ).config.get("port", 10443)
        return ConfigFragment(
            inbounds=[
                {
                    "type": "extension",
                    "tag": "extension-in",
                    "listen": "::",
                    "listen_port": port,
                },
            ],
        )

    def set_mode(self, *, state, mode) -> bool:
        state.protocols["extension"].config["mode"] = mode
        return True

    def read_mode(self, *, state) -> str:
        return str(state.protocols["extension"].config.get("mode", ""))

    def rotate(self) -> int:
        self.rotations += 1
        return self.rotations

    @staticmethod
    def refresh_due(*, state, forced: bool = False) -> bool:
        del state
        return forced

    @staticmethod
    def refresh(*, state) -> tuple[bool, str]:
        del state
        return True, "refreshed"


def test_one_descriptor_enables_commands_queries_actions_and_setup() -> None:
    plugin = ExtensionPlugin()
    state = AppState(
        protocols={
            "extension": PluginState(
                installed=True,
                enabled=False,
                config={"domain": "VPN.Example.COM."},
            ),
        },
    )
    get_plugin = lambda name: plugin if name == "extension" else None
    saved: list[AppState] = []

    commands = PluginCommandService(
        get_plugin=get_plugin,
        apply_config=lambda current: True,
        save_state=saved.append,
    )
    queries = PluginQueryService(get_plugin=get_plugin)
    actions = PluginActionService(get_plugin=get_plugin)
    certificates = type(
        "Certificates",
        (),
        {
            "ensure": staticmethod(
                lambda domain, config: ("/cert.pem", "/key.pem"),
            ),
        },
    )()

    ProtocolSetupService(certificates, get_plugin).prepare_enable(
        state,
        "extension",
    )
    assert state.protocols["extension"].config == {
        "domain": "vpn.example.com",
        "mode": "safe",
        "cert_file": "/cert.pem",
        "key_file": "/key.pem",
    }
    assert commands.execute(
        state,
        "extension",
        "set_mode",
        mode="fast",
    )
    assert queries.execute(
        "extension",
        "read_mode",
        state=state,
    ) == "fast"
    assert actions.execute("extension", "rotate") == 1
    assert saved == [state]
    PluginCatalog([plugin]).validate_contracts()


def test_default_composition_accepts_an_outer_plugin_factory() -> None:
    plugins = default_plugins(extra_factories=(ExtensionPlugin,))

    assert plugins[-1].meta.name == "extension"
    PluginCatalog(plugins).validate_contracts()


def test_production_bootstrap_accepts_an_outer_plugin_factory() -> None:
    application = production_application(
        extra_plugin_factories=(ExtensionPlugin,),
    )

    assert isinstance(
        application.protocols.get("extension"),
        ExtensionPlugin,
    )
    assert any(
        job.plugin_name == "extension" and job.action == "refresh"
        for job in application.protocols.maintenance_jobs()
    )
    assert any(
        resource.owner == "extension"
        and resource.path == "/etc/extension/config.toml"
        for resource in application.backups.policy.resources
    )
    assert application.protocols.display_name("extension") == (
        "Extension Transport"
    )


def test_external_factory_inbound_reaches_the_generic_config_pipeline() -> None:
    plugin = ExtensionPlugin()
    host = type("Host", (), {"which": staticmethod(lambda _name: None)})()
    container = PluginContainer([plugin], host=host)
    state = AppState(
        protocols={
            "extension": PluginState(
                enabled=True,
                config={"port": 15443},
            ),
        },
    )

    fragments = container.collect_fragments(state)
    config = singbox_config.generate_config(state, fragments)

    assert fragments["extension"].inbounds[0]["listen_port"] == 15443
    assert any(
        inbound.get("tag") == "extension-in"
        for inbound in config["inbounds"]
    )


def test_descriptor_drives_background_maintenance_without_scheduler_edits() -> None:
    plugin = ExtensionPlugin()
    host = type("Host", (), {"which": staticmethod(lambda _name: None)})()
    container = PluginContainer([plugin], host=host)
    protocols = ProtocolService(object(), container)
    operations = default_sync_operations(
        protocols=protocols,
        plugin_actions=PluginActionService(get_plugin=container.get),
        plugin_queries=PluginQueryService(get_plugin=container.get),
        apply_config=lambda state: True,
        check_traffic_limits=lambda state: [],
        inspect_certificates=lambda state: [],
        renew_subscription_certificate=lambda domain: (True, ""),
    )
    state = AppState(
        protocols={"extension": PluginState(enabled=True)},
    )

    skipped = operations.run_maintenance(state, False)
    completed = operations.run_maintenance(state, True)

    assert skipped[0].status == "fresh"
    assert completed[0].status == "success"
    assert completed[0].apply_required is True


def test_composition_owned_container_has_no_global_registration() -> None:
    plugin = ExtensionPlugin()
    host = type("Host", (), {"which": staticmethod(lambda _name: None)})()
    container = PluginContainer([plugin], host=host)

    assert container.get("extension") is plugin
    assert container.all_plugins() == [plugin]


def test_composition_rejects_duplicate_plugin_names() -> None:
    host = type("Host", (), {"which": staticmethod(lambda _name: None)})()

    try:
        PluginContainer(
            [ExtensionPlugin(), ExtensionPlugin()],
            host=host,
        )
    except ValueError as exc:
        assert "duplicate plugin names: extension" in str(exc)
    else:
        raise AssertionError("duplicate plugin names must fail composition")


def test_neutral_catalog_does_not_import_concrete_plugins() -> None:
    path = ROOT / "hydra" / "plugins" / "catalog.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    concrete_imports: list[str] = []
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        concrete_imports.extend(
            module
            for module in modules
            if module.startswith("hydra.plugins.")
            and module.endswith(".plugin")
        )
    assert concrete_imports == []


def test_core_and_services_do_not_import_concrete_plugins() -> None:
    violations: list[str] = []
    concrete_roots = {
        path.parent.name
        for path in (ROOT / "hydra" / "plugins").glob("*/plugin.py")
    }
    for layer in ("core", "services"):
        for path in sorted((ROOT / "hydra" / layer).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.append(node.module)
                for module in modules:
                    parts = module.split(".")
                    if (
                        len(parts) >= 3
                        and parts[:2] == ["hydra", "plugins"]
                        and parts[2] in concrete_roots
                    ):
                        violations.append(
                            f"{path.relative_to(ROOT)}:{node.lineno} "
                            f"{module}",
                        )

    assert violations == [], (
        "central layers import concrete plugins: "
        + ", ".join(violations)
    )


def test_production_composition_does_not_import_global_registry() -> None:
    path = ROOT / "hydra" / "bootstrap.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "production_application"
    )
    imported: list[str] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert "hydra.plugins.registry" not in imported
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "hydra.plugins"
        and any(alias.name == "registry" for alias in node.names)
        for node in ast.walk(function)
    )


def test_services_do_not_reintroduce_central_plugin_allowlists() -> None:
    for filename, forbidden in (
        ("plugin_commands.py", "PLUGIN_COMMANDS"),
        ("plugin_queries.py", "PLUGIN_QUERIES"),
        ("plugin_actions.py", "PLUGIN_ACTIONS"),
    ):
        source = (
            ROOT / "hydra" / "services" / filename
        ).read_text(encoding="utf-8")
        assert forbidden not in source

    traffic_path = ROOT / "hydra" / "services" / "traffic.py"
    traffic_source = traffic_path.read_text(encoding="utf-8")
    traffic_tree = ast.parse(traffic_source)
    refresh = next(
        node
        for node in traffic_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "refresh_user_traffic"
    )
    assert "_SNAPSHOT_PROTOCOLS" not in traffic_source
    assert {
        node.func.attr
        for node in ast.walk(refresh)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    } >= {
        "ingest_traffic",
        "traffic_snapshot",
        "aggregate_traffic_snapshot",
    }


def test_plugin_enablement_has_one_persisted_source_of_truth() -> None:
    state = AppState()
    assert not hasattr(state, "security")
    assert not {
        "warp_enabled",
        "dnscrypt_enabled",
    } & set(state.network.__dataclass_fields__)

    lifecycle = (
        ROOT / "hydra" / "services" / "plugin_lifecycle.py"
    ).read_text(encoding="utf-8")
    for legacy_field in (
        "_set_legacy_enablement_flags",
        "fail2ban_enabled",
        "honeypot_enabled",
        "ipban_enabled",
        "antidpi_enabled",
        "warp_enabled",
        "dnscrypt_enabled",
    ):
        assert legacy_field not in lifecycle


def test_subscription_iteration_has_no_protocol_name_branch() -> None:
    for filename in ("links.py", "client_configs.py"):
        path = ROOT / "hydra" / "services" / "subscriptions" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"))
        violations: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            expression = ast.unparse(node.left)
            if expression == "plugin.meta.name":
                violations.append(node.lineno)
        assert violations == [], f"{filename}: {violations}"


def test_special_menu_dispatch_is_data_driven() -> None:
    path = ROOT / "hydra" / "ui" / "_menus" / "plugin_dispatch.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "open_special_plugin_menu"
    )
    comparisons = [
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.Compare)
        and "plugin.meta.name" in ast.unparse(node)
    ]
    assert comparisons == []


def test_security_menu_uses_the_complete_plugin_category() -> None:
    from hydra.ui._menus.security import _security_plugins

    extension = type(
        "SecurityPlugin",
        (),
        {
            "meta": PluginMeta(
                name="extension-security",
                description="extension security",
                category=PluginCategory.SECURITY,
            ),
        },
    )()
    application = type(
        "Application",
        (),
        {
            "protocols": type(
                "Protocols",
                (),
                {"list": staticmethod(lambda category: [extension])},
            )(),
        },
    )()

    assert _security_plugins(application) == [extension]


def test_generic_ui_layers_have_no_builtin_protocol_allowlist() -> None:
    builtin_names = {
        "amneziawg",
        "anytls",
        "trusttunnel",
        "shadowtls",
        "hysteria2",
        "snell",
        "mieru",
        "naive",
        "telemt",
        "wdtt",
        "warp",
        "dnscrypt",
        "fail2ban",
        "honeypot",
        "ipban",
        "antidpi",
    }
    generic_modules = (
        "protocols.py",
        "monitoring_connections.py",
        "monitoring_services.py",
        "monitoring_traffic.py",
        "security.py",
        "users_overview.py",
        "users_management.py",
        "users_links.py",
    )
    violations: list[str] = []
    root = ROOT / "hydra" / "ui" / "_menus"
    for filename in generic_modules:
        tree = ast.parse((root / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.casefold() in builtin_names
            ):
                violations.append(f"{filename}:{node.lineno} {node.value}")

    assert violations == [], (
        "generic UI contains a concrete protocol allowlist: "
        + ", ".join(violations)
    )


def test_shared_scheduler_has_no_builtin_protocol_name_branch() -> None:
    builtin_names = {
        "amneziawg",
        "anytls",
        "trusttunnel",
        "shadowtls",
        "hysteria2",
        "snell",
        "mieru",
        "naive",
        "telemt",
        "wdtt",
        "warp",
        "dnscrypt",
        "fail2ban",
        "honeypot",
        "ipban",
        "antidpi",
    }
    violations: list[str] = []
    for filename in ("sync_cycle.py", "sync_ports.py"):
        path = ROOT / "hydra" / "services" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.casefold() in builtin_names
            ):
                violations.append(f"{filename}:{node.lineno} {node.value}")
    assert violations == []
