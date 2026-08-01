"""Architecture guards for the subscription service package."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from hydra.services.subscriptions import generator


PACKAGE = Path("hydra/services/subscriptions")
GENERATION_FUNCTIONS = (
    generator.generate_links,
    generator.generate_base64_sub,
    generator.generate_throne_sub,
    generator.generate_nekobox_sub,
    generator.generate_singbox_config,
    generator.generate_hydrabox_subscription,
    generator.generate_client_config,
)


def _modules() -> dict[str, Path]:
    return {
        path.stem: path
        for path in PACKAGE.glob("*.py")
        if path.name != "__init__.py"
    }


def test_subscription_modules_stay_cohesive_and_bounded():
    for path in _modules().values():
        source = path.read_text(encoding="utf-8")
        assert len(source.splitlines()) <= 400, path
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert node.end_lineno is not None
                assert node.end_lineno - node.lineno + 1 <= 120, (
                    path,
                    node.name,
                )


def test_subscription_package_has_no_hidden_plugin_globals():
    forbidden_imports = {
        "hydra.plugins.registry",
        "hydra.plugins.catalog",
    }
    for path in _modules().values():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {
                    alias.name for alias in node.names
                } & forbidden_imports, path
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_imports, path
            if isinstance(node, ast.Name):
                assert node.id != "DEFAULT_INVOKER", path


def test_subscription_implementation_modules_are_reachable():
    modules = _modules()
    imported: set[str] = set()
    prefix = "hydra.services.subscriptions."
    for path in modules.values():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith(prefix):
                    imported.add(node.module.removeprefix(prefix).split(".", 1)[0])
    assert set(modules) - {"generator"} <= imported


def test_generator_is_a_thin_compatibility_facade():
    source = Path(generator.__file__).read_text(encoding="utf-8")
    assert len(source.splitlines()) <= 120
    tree = ast.parse(source)
    functions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    assert functions == []
    assert all(
        function.__module__ != generator.__name__
        for function in GENERATION_FUNCTIONS
    )


def test_generation_requires_explicit_plugin_access():
    for function in GENERATION_FUNCTIONS:
        parameter = inspect.signature(function).parameters["plugins"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
