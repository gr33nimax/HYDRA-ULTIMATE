"""Architecture guards for the modular AmneziaWG implementation."""
from __future__ import annotations

import ast
import copy
import inspect
import textwrap
from pathlib import Path

from hydra.plugins.amneziawg.client_links import AwgClientLinksMixin
from hydra.plugins.amneziawg.configuration import AwgConfigurationMixin
from hydra.plugins.amneziawg.installation import AwgInstallationMixin
from hydra.plugins.amneziawg.observation import AwgObservationMixin
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.amneziawg.profiles import AwgProfileMixin
from hydra.plugins.amneziawg.runtime import AwgRuntimeMixin


_PACKAGE = Path(inspect.getfile(AmneziaWGPlugin)).parent
_CAPABILITY_CLASSES = (
    AmneziaWGPlugin,
    AwgInstallationMixin,
    AwgConfigurationMixin,
    AwgProfileMixin,
    AwgClientLinksMixin,
    AwgObservationMixin,
    AwgRuntimeMixin,
)


def _defined_methods(owner: type) -> dict[str, object]:
    return {
        name: getattr(owner, name)
        for name, value in owner.__dict__.items()
        if inspect.isfunction(value)
        or isinstance(value, (staticmethod, classmethod))
    }


def _method_node(method: object) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


_METHOD_OWNERS: dict[str, type] = {}
_METHODS: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
for _owner in _CAPABILITY_CLASSES:
    for _name, _method in _defined_methods(_owner).items():
        assert _name not in _METHODS, (
            f"duplicate AWG method owner: {_name} is defined by "
            f"{_METHOD_OWNERS[_name].__name__} and {_owner.__name__}"
        )
        _METHOD_OWNERS[_name] = _owner
        _METHODS[_name] = _method_node(_method)


def _tree(method_name: str) -> ast.AST:
    return ast.parse(
        textwrap.dedent(
            inspect.getsource(getattr(AmneziaWGPlugin, method_name))
        )
    )


def _called_names(method_name: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_tree(method_name)):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _reachable_methods(*roots: str) -> set[str]:
    reachable: set[str] = set()
    pending = list(roots)
    while pending:
        method_name = pending.pop()
        if method_name in reachable or method_name not in _METHODS:
            continue
        reachable.add(method_name)
        for node in ast.walk(_METHODS[method_name]):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"self", "cls"}
            ):
                pending.append(node.func.attr)
    return reachable


def _transitive_runtime_mutations(root: str) -> list[str]:
    forbidden_calls = {
        "apply",
        "apply_config",
        "apply_configuration",
        "chmod",
        "mkdir",
        "save_state",
        "unlink",
        "write_bytes",
        "write_text",
    }
    mutating_commands = {"cp", "iptables", "mv", "rm", "systemctl"}
    violations: list[str] = []
    for method_name in _reachable_methods(root):
        for node in ast.walk(_METHODS[method_name]):
            if isinstance(node, ast.Call):
                called = None
                if isinstance(node.func, ast.Name):
                    called = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    called = node.func.attr
                if called in forbidden_calls:
                    violations.append(f"{method_name}:{called}")
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in mutating_commands
            ):
                violations.append(f"{method_name}:command:{node.value}")
    return violations


def test_facade_mounts_each_cohesive_production_capability_once():
    expected_mixins = _CAPABILITY_CLASSES[1:]
    assert AmneziaWGPlugin.__mro__[1 : 1 + len(expected_mixins)] == (
        expected_mixins
    )
    for owner in expected_mixins:
        for method_name, method in _defined_methods(owner).items():
            assert getattr(AmneziaWGPlugin, method_name) is method


def test_awg_modules_and_functions_stay_bounded():
    for path in _PACKAGE.glob("*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) <= 550, f"{path.name}: {len(lines)} lines"
        tree = ast.parse("\n".join(lines))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                span = node.end_lineno - node.lineno + 1
                assert span <= 100, f"{path.name}:{node.name}: {span} lines"
    plugin_lines = (
        (_PACKAGE / "plugin.py").read_text(encoding="utf-8").splitlines()
    )
    assert len(plugin_lines) <= 150


def test_capability_modules_do_not_import_the_facade_backwards():
    for path in _PACKAGE.glob("*.py"):
        if path.name == "plugin.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in {
                    "plugin",
                    "hydra.plugins.amneziawg.plugin",
                }, path.name
            if isinstance(node, ast.Import):
                assert all(
                    alias.name != "hydra.plugins.amneziawg.plugin"
                    for alias in node.names
                ), path.name


def test_awg_internal_module_graph_is_acyclic():
    modules = {path.stem: path for path in _PACKAGE.glob("*.py")}
    edges = {module: set() for module in modules}
    for module, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level
                and node.module
            ):
                target = node.module.split(".", 1)[0]
                if target in modules:
                    edges[module].add(target)

    visited: set[str] = set()
    active: list[str] = []

    def visit(module: str) -> None:
        if module in active:
            cycle = " -> ".join(active[active.index(module) :] + [module])
            raise AssertionError(f"AWG import cycle: {cycle}")
        if module in visited:
            return
        active.append(module)
        for dependency in edges[module]:
            visit(dependency)
        active.pop()
        visited.add(module)

    for module in edges:
        visit(module)


def test_all_private_capability_helpers_are_on_a_production_path():
    roots = {
        method_name
        for method_name in _METHODS
        if not method_name.startswith("_")
    } | {"__init__"}
    reachable = _reachable_methods(*roots)
    orphaned = {
        method_name
        for method_name in _METHODS
        if method_name.startswith("_")
        and method_name != "__init__"
        and method_name not in reachable
    }
    assert not orphaned


def test_awg_package_has_no_duplicate_function_implementations():
    fingerprints: dict[str, str] = {}
    for path in _PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            normalized = copy.deepcopy(node)
            normalized.name = "_"
            fingerprint = ast.dump(normalized, include_attributes=False)
            location = f"{path.name}:{node.name}"
            assert fingerprint not in fingerprints, (
                f"{location} duplicates {fingerprints.get(fingerprint)}"
            )
            fingerprints[fingerprint] = location


def test_render_and_query_hooks_do_not_provision_or_persist():
    forbidden = {
        "_generate_keys",
        "_generate_private_key",
        "_provision_user_keys",
        "_provision_user_profiles",
        "save_state",
        "apply",
        "apply_config",
        "apply_configuration",
        "write_text",
        "write_bytes",
        "unlink",
        "chmod",
        "mkdir",
    }
    for method_name in (
        "configure",
        "_generate_config_for_iface",
        "generate_client_config",
        "client_link",
        "amnezia_link",
        "get_profiles",
        "traffic",
        "connected_clients",
    ):
        assert not (_called_names(method_name) & forbidden), method_name


def test_render_queries_and_commands_are_transitively_runtime_pure():
    for method_name in (
        "configure",
        "generate_client_config",
        "client_link",
        "amnezia_link",
        "get_profiles",
        "traffic",
        "connected_clients",
        "add_profile",
        "remove_profile",
        "rotate_obfuscation",
    ):
        assert not _transitive_runtime_mutations(method_name), method_name


def test_profile_commands_have_no_runtime_or_persistence_callbacks():
    forbidden = {
        "save_state",
        "apply",
        "apply_config",
        "apply_configuration",
        "write_text",
        "write_bytes",
        "unlink",
        "chmod",
        "mkdir",
    }
    for method_name in ("add_profile", "remove_profile", "rotate_obfuscation"):
        signature = inspect.signature(getattr(AmneziaWGPlugin, method_name))
        assert "apply_configuration" not in signature.parameters
        assert not (_called_names(method_name) & forbidden), method_name
        literals = {
            node.value
            for node in ast.walk(_tree(method_name))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert "systemctl" not in literals


def test_apply_is_the_profile_runtime_reconciler():
    calls = _called_names("apply")
    assert "write_text" in calls
    assert "unlink" in calls
    literals = {
        node.value
        for node in ast.walk(_tree("apply"))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "systemctl" in literals


def test_lifecycle_hooks_do_not_call_other_lifecycle_hooks():
    hooks = {
        "on_user_add",
        "on_user_remove",
        "on_user_block",
        "on_enable",
        "on_disable",
    }
    for hook in hooks:
        assert not ((_called_names(hook) & hooks) - {hook}), hook
