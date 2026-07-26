"""Repository-wide dependency graph invariants."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = ROOT / "hydra"


def _modules() -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in PACKAGE_ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if path.name == "__init__.py":
            name = ".".join(relative.parent.parts)
        else:
            name = ".".join(relative.with_suffix("").parts)
        result[name] = path
    return result


def _import_targets(
    module: str,
    path: Path,
    tree: ast.AST,
    modules: dict[str, Path],
) -> set[str]:
    package = (
        module.split(".")
        if path.name == "__init__.py"
        else module.split(".")[:-1]
    )
    targets: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                keep = max(0, len(package) - node.level + 1)
                base = ".".join(
                    [
                        *package[:keep],
                        *([base] if base else []),
                    ],
                )
            if base:
                names.append(base)
                names.extend(
                    f"{base}.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
        for name in names:
            candidate = name
            while candidate and candidate not in modules:
                candidate = candidate.rpartition(".")[0]
            if candidate in modules and candidate != module:
                targets.add(candidate)
    return targets


def _dependency_graph() -> dict[str, set[str]]:
    modules = _modules()
    return {
        module: _import_targets(
            module,
            path,
            ast.parse(path.read_text(encoding="utf-8")),
            modules,
        )
        for module, path in modules.items()
    }


def _layer_import_violations(
    layer: str,
    forbidden: tuple[str, ...],
    *,
    allowed_sources: frozenset[str] = frozenset(),
) -> list[str]:
    violations: list[str] = []
    for path in sorted((PACKAGE_ROOT / layer).rglob("*.py")):
        source = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        if source in allowed_sources:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if any(
                    module == prefix or module.startswith(prefix + ".")
                    for prefix in forbidden
                ):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} {module}",
                    )
    return violations


def _strongly_connected_components(
    graph: dict[str, set[str]],
) -> list[list[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    active: set[str] = set()
    result: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        active.add(node)

        for target in graph[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in active:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] != indices[node]:
            return
        component: list[str] = []
        while True:
            current = stack.pop()
            active.remove(current)
            component.append(current)
            if current == node:
                break
        result.append(sorted(component))

    for node in graph:
        if node not in indices:
            visit(node)
    return result


def test_internal_import_graph_is_acyclic():
    cycles = [
        component
        for component in _strongly_connected_components(
            _dependency_graph(),
        )
        if len(component) > 1
    ]
    assert cycles == [], "internal dependency cycles: " + "; ".join(
        " -> ".join(component)
        for component in cycles
    )


def test_services_never_import_outer_adapters_or_composition():
    violations = _layer_import_violations(
        "services",
        ("hydra.ui", "hydra.entrypoints", "hydra.bootstrap"),
        allowed_sources=frozenset(
            {"hydra.services.telegram.admin_bot_entrypoint"},
        ),
    )
    assert violations == [], "service layer imports an adapter: " + ", ".join(
        violations,
    )


def test_plugins_never_import_services_or_executable_entrypoints():
    violations = _layer_import_violations(
        "plugins",
        ("hydra.services", "hydra.entrypoints"),
    )
    assert violations == [], "plugin layer imports an outer layer: " + ", ".join(
        violations,
    )


def test_contracts_are_independent_of_implementation_layers():
    violations = _layer_import_violations(
        "contracts",
        (
            "hydra.core",
            "hydra.plugins",
            "hydra.services",
            "hydra.ui",
            "hydra.entrypoints",
        ),
    )
    assert violations == [], "contract layer imports implementation: " + ", ".join(
        violations,
    )


def test_core_never_imports_outer_layers_except_legacy_facade():
    violations = _layer_import_violations(
        "core",
        (
            "hydra.plugins",
            "hydra.services",
            "hydra.ui",
            "hydra.entrypoints",
        ),
        allowed_sources=frozenset({"hydra.core.orchestrator"}),
    )
    assert violations == [], "core layer imports an outer layer: " + ", ".join(
        violations,
    )
