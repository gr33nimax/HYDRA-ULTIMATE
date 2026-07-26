"""Generic architecture guards for plugin query and lifecycle purity."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
PLUGIN_ROOT = ROOT / "hydra" / "plugins"
QUERY_HOOKS = {
    "client_link",
    "client_links",
    "configure",
    "connected_clients",
    "generate_client_config",
    "healthcheck",
    "healthcheck_for_state",
    "status",
    "traffic",
    "traffic_snapshot",
    "aggregate_traffic_snapshot",
}
LIFECYCLE_HOOKS = {
    "on_disable",
    "on_enable",
    "on_install",
    "on_uninstall",
    "on_user_add",
    "on_user_block",
    "on_user_remove",
    "on_user_unblock",
}
STATE_MUTATORS = {
    "add",
    "append",
    "clear",
    "discard",
    "extend",
    "insert",
    "pop",
    "popitem",
    "remove",
    "reverse",
    "setdefault",
    "sort",
    "update",
}
RUNTIME_MUTATORS = {
    "apply_config",
    "apply_configuration",
    "chmod",
    "close_range",
    "close_tcp",
    "close_udp",
    "mkdir",
    "open_range",
    "open_tcp",
    "open_udp",
    "rename",
    "rmdir",
    "rmtree",
    "save_state",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}


def _plugin_classes():
    for path in sorted(PLUGIN_ROOT.glob("*/plugin.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                methods = {
                    child.name: child
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                if methods:
                    yield path, node, methods


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _aliases_tainted(node: ast.AST, tainted: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _aliases_tainted(node.value, tainted)
    if isinstance(node, ast.Call):
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"get", "setdefault"}
            and _aliases_tainted(node.func.value, tainted)
        )
    if isinstance(node, ast.IfExp):
        return (
            _aliases_tainted(node.body, tainted)
            or _aliases_tainted(node.orelse, tainted)
        )
    return False


def _tainted_names(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
    seeds: set[str],
) -> set[str]:
    tainted = {
        argument.arg
        for argument in method.args.args
        if argument.arg in seeds
    }
    changed = True
    while changed:
        changed = False
        for node in ast.walk(method):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if node.value is None or not _aliases_tainted(node.value, tainted):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in tainted:
                    tainted.add(target.id)
                    changed = True
    return tainted


def _state_mutations(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    seeds: set[str],
) -> list[int]:
    tainted = _tainted_names(method, seeds)
    violations: list[int] = []
    for node in ast.walk(method):
        targets: list[ast.AST] = []
        if isinstance(node, (ast.Assign, ast.Delete)):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for target in targets:
            if (
                not isinstance(target, ast.Name)
                and _root_name(target) in tainted
            ):
                violations.append(node.lineno)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in STATE_MUTATORS
            and _root_name(node.func.value) in tainted
        ):
            violations.append(node.lineno)
    return violations


def _self_edges(
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, set[str]]:
    edges = {name: set() for name in methods}
    for name, method in methods.items():
        for node in ast.walk(method):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"self", "cls"}
                and node.func.attr in methods
            ):
                edges[name].add(node.func.attr)
    return edges


def _reachable(root: str, edges: dict[str, set[str]]) -> set[str]:
    result: set[str] = set()
    pending = [root]
    while pending:
        name = pending.pop()
        if name in result:
            continue
        result.add(name)
        pending.extend(edges.get(name, ()))
    return result


def _literal_command(node: ast.Call) -> list[str] | None:
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return None
    command: list[str] = []
    for item in node.args[0].elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        command.append(item.value)
    return command


def _mutating_host_call(node: ast.Call) -> bool:
    called = _call_name(node.func)
    if called == "HOST.systemd":
        return bool(
            node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value not in {"is-active", "is-enabled", "status"}
        )
    if called not in {"HOST.run", "_run", "subprocess.run", "subprocess.Popen"}:
        return False
    command = _literal_command(node)
    if not command:
        return False
    executable = command[0]
    if executable == "systemctl":
        return len(command) < 2 or command[1] not in {
            "is-active",
            "is-enabled",
            "status",
        }
    if executable in {"iptables", "ip6tables"}:
        return not any(flag in command for flag in {"-C", "-L", "-S"})
    if executable == "ipset":
        return len(command) < 2 or command[1] != "list"
    return executable in {
        "apt",
        "apt-get",
        "cp",
        "dnf",
        "install",
        "kill",
        "modprobe",
        "mv",
        "nft",
        "rm",
        "service",
        "sysctl",
        "tee",
        "yum",
    }


def _runtime_mutations(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[int]:
    violations: list[int] = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        called = _call_name(node.func).rsplit(".", 1)[-1]
        if called in RUNTIME_MUTATORS or _mutating_host_call(node):
            violations.append(node.lineno)
    return violations


def _parents(root: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node
        for node in ast.walk(root)
        for child in ast.iter_child_nodes(node)
    }


def _is_state_none_test(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "state"
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Is)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value is None
    )


def _guarded_state_reloads(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[int]:
    if not any(argument.arg == "state" for argument in method.args.args):
        return []
    parents = _parents(method)
    violations: list[int] = []
    for node in ast.walk(method):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "load_state"
        ):
            continue
        current: ast.AST | None = node
        guarded = False
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.If) and _is_state_none_test(current.test):
                guarded = True
                break
        if not guarded:
            violations.append(node.lineno)
    return violations


def test_query_hooks_are_transitively_state_and_runtime_pure():
    violations: list[str] = []
    for path, class_node, methods in _plugin_classes():
        edges = _self_edges(methods)
        relative = path.relative_to(ROOT)
        for root in sorted(QUERY_HOOKS & methods.keys()):
            for name in _reachable(root, edges):
                method = methods[name]
                for line in _state_mutations(
                    method,
                    seeds={"state", "user"},
                ):
                    violations.append(
                        f"{relative}:{line} {class_node.name}.{root}->{name} state",
                    )
                for line in _runtime_mutations(method):
                    violations.append(
                        f"{relative}:{line} {class_node.name}.{root}->{name} runtime",
                    )
    assert violations == [], "\n".join(violations)


def test_state_aware_query_reloads_are_none_only_fallbacks():
    violations: list[str] = []
    for path, class_node, methods in _plugin_classes():
        relative = path.relative_to(ROOT)
        for name in QUERY_HOOKS & methods.keys():
            for line in _guarded_state_reloads(methods[name]):
                violations.append(
                    f"{relative}:{line} {class_node.name}.{name}",
                )
    assert violations == [], "\n".join(violations)


def test_lifecycle_hooks_do_not_mutate_desired_state_or_chain_hooks():
    violations: list[str] = []
    for path, class_node, methods in _plugin_classes():
        edges = _self_edges(methods)
        relative = path.relative_to(ROOT)
        for root in sorted(LIFECYCLE_HOOKS & methods.keys()):
            for called in edges[root] & LIFECYCLE_HOOKS:
                violations.append(
                    f"{relative}:{methods[root].lineno} "
                    f"{class_node.name}.{root}->{called}",
                )
            for name in _reachable(root, edges):
                for line in _state_mutations(methods[name], seeds={"state"}):
                    violations.append(
                        f"{relative}:{line} "
                        f"{class_node.name}.{root}->{name}",
                    )
    assert violations == [], "\n".join(violations)


def test_status_contract_accepts_explicit_optional_state():
    violations: list[str] = []
    for path, class_node, methods in _plugin_classes():
        status = methods.get("status")
        if status is None:
            continue
        arguments = {argument.arg for argument in status.args.args}
        if "state" not in arguments:
            violations.append(
                f"{path.relative_to(ROOT)}:{status.lineno} {class_node.name}",
            )
    assert violations == [], "\n".join(violations)


def test_runtime_to_desired_compatibility_methods_are_gone():
    from hydra.plugins.naive.plugin import NaivePlugin
    from hydra.plugins.wdtt.plugin import WdttPlugin

    assert not hasattr(NaivePlugin, "update_traffic")
    assert not hasattr(WdttPlugin, "sync_fs_to_state")
