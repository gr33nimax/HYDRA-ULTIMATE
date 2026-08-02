import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def test_transport_layers_do_not_reintroduce_global_application_services():
    files = [ROOT / "hydra" / "cli.py", ROOT / "hydra" / "ui" / "menus.py"]
    forbidden = ("APP = production_application()", "_user_service =", "_protocol_service =")
    violations = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        for marker in forbidden:
            if marker in source:
                violations.append(f"{path.relative_to(ROOT)}: {marker}")
    assert violations == [], "global application services returned: " + ", ".join(violations)


def test_version_is_consistent_across_runtime_and_entrypoint():
    from hydra import __version__

    entrypoint = (ROOT / "main.py").read_text(encoding="utf-8")
    assert __version__ == "2.6.0"
    assert f"HYDRA v{__version__}" in entrypoint


def test_operational_documentation_is_kept_with_the_repository():
    cli = ROOT / "docs" / "CLI.md"
    text = cli.read_text(encoding="utf-8")
    assert "hydra apply" in text
    assert "tls_mux" in text

    extension = (ROOT / "docs" / "PLUGIN_DEVELOPMENT.md").read_text(
        encoding="utf-8",
    )
    for contract in (
        "PluginContainer",
        "ConfigFragment.inbounds",
        "app.plugin_command",
        "ConnectionAttributor",
        "ruff check .",
    ):
        assert contract in extension


def test_management_adapters_use_the_application_boundary_for_lifecycle():
    forbidden = {
        "apply_config",
        "install_plugin",
        "uninstall_plugin",
        "reinstall_plugin",
        "enable",
        "disable",
    }
    violations: list[str] = []
    for relative in ("hydra/ui/menus.py", "hydra/services/telegram/bot.py"):
        path = ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callback = node.func
            if (
                isinstance(callback, ast.Attribute)
                and isinstance(callback.value, ast.Name)
                and callback.value.id == "orchestrator"
                and callback.attr in forbidden
            ):
                violations.append(f"{relative}:{node.lineno} orchestrator.{callback.attr}")
    assert violations == [], "application boundary bypassed: " + ", ".join(violations)


def test_production_code_does_not_import_the_core_orchestrator_shim():
    violations: list[str] = []
    production_paths = [
        ROOT / "main.py",
        *sorted((ROOT / "hydra").rglob("*.py")),
    ]
    for path in production_paths:
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports_orchestrator = (
                isinstance(node, ast.Import)
                and any(alias.name == "hydra.core.orchestrator" for alias in node.names)
            ) or (
                isinstance(node, ast.ImportFrom)
                and (
                    node.module == "hydra.core.orchestrator"
                    or (
                        node.module == "hydra.core"
                        and any(alias.name == "orchestrator" for alias in node.names)
                    )
                )
            )
            if imports_orchestrator:
                violations.append(f"{relative}:{node.lineno}")
    assert violations == [], "production code imports compatibility shim: " + ", ".join(violations)


def test_production_code_has_no_default_plugin_invoker_singleton():
    violations: list[str] = []
    for path in sorted((ROOT / "hydra").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "DEFAULT_INVOKER":
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}",
                )
            elif isinstance(node, ast.ImportFrom) and any(
                alias.name == "DEFAULT_INVOKER"
                for alias in node.names
            ):
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}",
                )
    assert violations == [], (
        "process-global PluginInvoker returned: " + ", ".join(violations)
    )


def test_global_plugin_registry_is_confined_to_compatibility_facade():
    allowed = {
        Path("hydra/services/orchestration.py"),
    }
    violations: list[str] = []
    for path in sorted((ROOT / "hydra").rglob("*.py")):
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports_registry = (
                isinstance(node, ast.Import)
                and any(
                    alias.name == "hydra.plugins.registry"
                    for alias in node.names
                )
            ) or (
                isinstance(node, ast.ImportFrom)
                and (
                    node.module == "hydra.plugins.registry"
                    or (
                        node.module == "hydra.plugins"
                        and any(
                            alias.name == "registry"
                            for alias in node.names
                        )
                    )
                )
            )
            if imports_registry and relative not in allowed:
                violations.append(f"{relative}:{node.lineno}")
    assert violations == [], (
        "production code imports global plugin registry: "
        + ", ".join(violations)
    )


def test_production_application_is_only_created_at_adapter_roots():
    allowed = {
        Path("main.py"),
        Path("hydra/bootstrap.py"),
        Path("hydra/cli.py"),
        Path("hydra/entrypoints/subscription_server.py"),
        Path("hydra/entrypoints/sync_agent.py"),
        Path("hydra/services/telegram/admin_bot_entrypoint.py"),
        Path("hydra/services/telegram/bot.py"),
        Path("hydra/ui/menus.py"),
    }
    violations: list[str] = []
    paths = [ROOT / "main.py", *sorted((ROOT / "hydra").rglob("*.py"))]
    for path in paths:
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mentions_factory = (
                isinstance(node, ast.Name)
                and node.id == "production_application"
            ) or (
                isinstance(node, ast.ImportFrom)
                and any(
                    alias.name == "production_application"
                    for alias in node.names
                )
            )
            if mentions_factory and relative not in allowed:
                violations.append(f"{relative}:{node.lineno}")
    assert violations == [], (
        "service locator escaped adapter roots: " + ", ".join(violations)
    )


def test_application_facade_does_not_assemble_production_dependencies():
    path = ROOT / "hydra" / "services" / "application.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "production_application" not in source
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module in {
            "hydra.plugins.container",
            "hydra.plugins.defaults",
            "hydra.services.admin_infrastructure",
            "hydra.services.orchestration_service",
        }
        for node in ast.walk(tree)
    )


def test_core_orchestrator_is_a_thin_module_alias():
    path = ROOT / "hydra" / "core" / "orchestrator.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert len(source.splitlines()) < 20
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        for node in tree.body
    )

    from hydra.core import orchestrator as compatibility_orchestrator
    from hydra.services import orchestration

    assert compatibility_orchestrator is orchestration


def test_core_dependency_boundary_has_no_upward_imports():
    forbidden_layers = {"plugins", "services", "ui"}
    shim = Path("hydra/core/orchestrator.py")
    violations: list[str] = []

    for path in sorted((ROOT / "hydra" / "core").rglob("*.py")):
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            else:
                continue

            compatibility_alias = (
                relative == shim
                and isinstance(node, ast.ImportFrom)
                and node.module == "hydra.services"
                and [alias.name for alias in node.names] == ["orchestration"]
            )
            if compatibility_alias:
                continue

            for module in imported:
                parts = module.split(".")
                absolute_upward_import = (
                    len(parts) > 1
                    and parts[0] == "hydra"
                    and parts[1] in forbidden_layers
                )
                relative_upward_import = (
                    isinstance(node, ast.ImportFrom)
                    and node.level > 1
                    and parts[0] in forbidden_layers
                )
                if absolute_upward_import or relative_upward_import:
                    violations.append(f"{relative}:{node.lineno} {module}")

    assert violations == [], "core imports higher layers: " + ", ".join(violations)


def test_plugin_state_port_does_not_expose_unrelated_application_state():
    from hydra.plugins.context import PluginStateAccess

    assert set(PluginStateAccess.__annotations__) == {
        "protocols",
        "users",
        "network",
    }


def test_registry_roles_remain_split_behind_the_compatibility_facade():
    registry = ROOT / "hydra" / "plugins" / "registry.py"
    assert len(registry.read_text(encoding="utf-8").splitlines()) < 140
    assert (ROOT / "hydra" / "plugins" / "catalog.py").is_file()
    assert (ROOT / "hydra" / "plugins" / "defaults.py").is_file()
    assert (ROOT / "hydra" / "plugins" / "executor.py").is_file()
    assert (ROOT / "hydra" / "plugins" / "invoker.py").is_file()


def test_menu_facade_is_decomposed_into_domain_controllers():
    facade = ROOT / "hydra" / "ui" / "menus.py"
    source = facade.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert len(source.splitlines()) < 250
    assert {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    } == {
        "_application",
        "_apply_error_text",
        "_bind_controller",
        "_make_binder",
        "_make_forwarder",
        "_open_diagnostics",
        "main_menu",
    }

    menu_root = ROOT / "hydra" / "ui" / "_menus"
    limits = {
        "client_status.py": 150,
        "core.py": 350,
        "extended_protocols.py": 950,
        "facade_contract.py": 250,
        "monitoring.py": 1000,
        "plugin_dispatch.py": 100,
        "protocols.py": 550,
        "root.py": 250,
        "security.py": 250,
        "telegram.py": 100,
        "users.py": 1000,
    }
    assert set(limits) <= {path.name for path in menu_root.glob("*.py")}
    for name, limit in limits.items():
        assert len(
            (menu_root / name).read_text(encoding="utf-8").splitlines(),
        ) < limit


def test_menu_layers_have_one_composition_root_and_no_hidden_host_access():
    facade = ROOT / "hydra" / "ui" / "menus.py"
    facade_tree = ast.parse(facade.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    production_calls = [
        node
        for node in ast.walk(facade_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "production_application"
    ]
    assert len(production_calls) == 1
    assert production_calls == [
        node
        for node in ast.walk(functions["main_menu"])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "production_application"
    ]

    forbidden_imports = {"hydra.core.host", "hydra.plugins.registry"}
    violations: list[str] = []
    paths = [
        facade,
        *sorted((ROOT / "hydra" / "ui" / "_menus").glob("*.py")),
    ]
    for path in paths:
        relative = path.relative_to(ROOT)
        module_tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(module_tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module in forbidden_imports:
                    violations.append(f"{relative}:{node.lineno} {module}")
            if (
                path != facade
                and isinstance(node, ast.Name)
                and node.id in {"HOST", "production_application"}
            ):
                violations.append(f"{relative}:{node.lineno} {node.id}")
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in {"p", "plugin"}
                and node.attr.startswith("_")
            ):
                violations.append(
                    f"{relative}:{node.lineno} {node.value.id}.{node.attr}",
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"p", "plugin"}
            ):
                violations.append(
                    f"{relative}:{node.lineno} concrete plugin call "
                    f"{node.func.value.id}.{node.func.attr}()",
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id.endswith("Plugin")
            ):
                violations.append(
                    f"{relative}:{node.lineno} {node.func.id}()",
                )
    assert violations == [], "menu boundary leak: " + ", ".join(violations)


def test_configuration_contracts_are_dependency_neutral():
    forbidden_roots = {"core", "plugins", "services", "ui"}
    violations: list[str] = []
    for path in sorted((ROOT / "hydra" / "contracts").rglob("*.py")):
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            for module in imported:
                parts = module.split(".")
                absolute_layer = (
                    len(parts) > 1
                    and parts[0] == "hydra"
                    and parts[1] in forbidden_roots
                )
                relative_layer = (
                    getattr(node, "level", 0) > 0 and parts[0] in forbidden_roots
                )
                if absolute_layer or relative_layer:
                    violations.append(f"{relative}:{node.lineno} {module}")
    assert violations == [], "contracts depend on a higher layer: " + ", ".join(violations)


def test_core_uses_neutral_configuration_contracts_not_plugin_facades():
    violations: list[str] = []
    for path in sorted((ROOT / "hydra" / "core").rglob("*.py")):
        relative = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "hydra.plugins.config":
                        violations.append(f"{relative}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "hydra.plugins.config":
                    violations.append(f"{relative}:{node.lineno} {node.module}")
                elif node.module == "hydra.plugins.base" and any(
                    alias.name in {"ConfigFragment", "*"} for alias in node.names
                ):
                    violations.append(
                        f"{relative}:{node.lineno} hydra.plugins.base.ConfigFragment"
                    )
    assert violations == [], "core imports plugin-owned contracts: " + ", ".join(violations)


def test_telegram_admin_adapter_is_split_behind_a_thin_facade():
    telegram_root = ROOT / "hydra" / "services" / "telegram"
    limits = {
        "bot.py": 350,
        "controller.py": 700,
        "dashboards.py": 800,
        "security_actions.py": 650,
        "sdk.py": 100,
    }
    for name, limit in limits.items():
        path = telegram_root / name
        assert path.is_file()
        assert len(path.read_text(encoding="utf-8").splitlines()) < limit


def test_telegram_admin_adapter_has_one_explicit_composition_root():
    telegram_root = ROOT / "hydra" / "services" / "telegram"
    internal_modules = (
        telegram_root / "controller.py",
        telegram_root / "dashboards.py",
        telegram_root / "security_actions.py",
    )
    violations: list[str] = []
    for path in internal_modules:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        if "production_application" in source:
            violations.append(f"{path.name}: production_application")
        if "hydra.plugins.registry" in source:
            violations.append(f"{path.name}: plugin registry")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
            )
            if called_name.endswith("Plugin"):
                violations.append(
                    f"{path.name}:{node.lineno} {called_name}()"
                )
            if (
                called_name == "status"
                and isinstance(node.func, ast.Attribute)
                and not _dotted_name(node.func).endswith(".protocols.status")
            ):
                violations.append(
                    f"{path.name}:{node.lineno} direct plugin status()"
                )

    facade_tree = ast.parse(
        (telegram_root / "bot.py").read_text(encoding="utf-8")
    )
    top_level_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    removed_dependency_free_shims = {
        "_fail2ban_monitor_worker",
        "_recent_fail2ban_bans",
    }
    exports_node = next(
        node
        for node in facade_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        )
    )
    facade_exports = set(ast.literal_eval(exports_node.value))
    production_calls = [
        node
        for node in ast.walk(facade_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "production_application"
    ]
    entrypoint_tree = ast.parse(
        (telegram_root / "admin_bot_entrypoint.py").read_text(
            encoding="utf-8",
        ),
    )
    entrypoint_calls = [
        node
        for node in ast.walk(entrypoint_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "production_application"
    ]

    assert violations == [], ", ".join(violations)
    assert removed_dependency_free_shims.isdisjoint(top_level_functions)
    assert removed_dependency_free_shims.isdisjoint(facade_exports)
    assert production_calls == []
    assert len(entrypoint_calls) == 1


def test_all_telegram_internals_use_application_boundaries():
    telegram_root = ROOT / "hydra" / "services" / "telegram"
    composition_modules = {
        "__init__.py",
        "admin_bot_entrypoint.py",
        "bot.py",
    }
    internal_modules = sorted(
        path
        for path in telegram_root.rglob("*.py")
        if path.name not in composition_modules
    )
    violations: list[str] = []
    for path in internal_modules:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if (
                        alias.name.startswith("hydra.plugins")
                        or alias.name == "hydra.core.host"
                        or alias.name in {
                            "os",
                            "pathlib",
                            "socket",
                            "subprocess",
                        }
                    ):
                        violations.append(
                            f"{path.name}:{node.lineno} import {alias.name}",
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if (
                    module.startswith("hydra.plugins")
                    or module == "hydra.core.host"
                    or module in {
                        "os",
                        "pathlib",
                        "socket",
                        "subprocess",
                    }
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} import {module}",
                    )
            elif isinstance(node, ast.Name) and node.id in {
                "DEFAULT_INVOKER",
                "HOST",
            }:
                violations.append(
                    f"{path.name}:{node.lineno} {node.id}",
                )
            elif isinstance(node, ast.Call):
                called = _dotted_name(node.func)
                if called.endswith(
                    (
                        ".protocols.get",
                        ".protocols.require",
                        ".protocols.list",
                        ".protocols.enabled",
                    ),
                ) or ".protocols.catalog." in called:
                    violations.append(
                        f"{path.name}:{node.lineno} leaks plugin object via {called}",
                    )
                if isinstance(node.func, ast.Attribute) and (
                    node.func.attr.startswith("_")
                    and _dotted_name(node.func.value) in {"plugin", "protocol"}
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} private plugin call {called}",
                    )
                if called in {"open", "io.open"} or called.endswith(
                    (
                        ".open",
                        ".read_bytes",
                        ".read_text",
                        ".stat",
                    ),
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} direct filesystem read {called}",
                    )
        for marker in (
            "._load_state(",
            "subprocess.run(",
            "subprocess.Popen(",
            "os.system(",
        ):
            if marker in source:
                violations.append(f"{path.name}: {marker}")

    assert internal_modules
    assert violations == [], "Telegram boundary bypasses: " + ", ".join(
        violations,
    )


def test_telegram_controller_requires_application_service():
    controller = ast.parse(
        (
            ROOT / "hydra" / "services" / "telegram" / "controller.py"
        ).read_text(encoding="utf-8")
    )
    admin_bot = next(
        node
        for node in controller.body
        if isinstance(node, ast.ClassDef) and node.name == "AdminBot"
    )
    initializer = next(
        node
        for node in admin_bot.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    arguments = [argument.arg for argument in initializer.args.args]
    assert "application" in arguments
