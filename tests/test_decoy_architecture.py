"""Architecture guards for the decomposed decoy-site generator."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
FACADE = ROOT / "hydra" / "core" / "decoy.py"
THEME_PACKAGE = ROOT / "hydra" / "core" / "decoy_sites"
IMPLEMENTATION_MODULES = {
    "__init__.py",
    "blog.py",
    "bootstrap.py",
    "docs.py",
    "landing.py",
    "status.py",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_decoy_facade_and_theme_modules_stay_bounded():
    assert len(FACADE.read_text(encoding="utf-8").splitlines()) < 80
    assert IMPLEMENTATION_MODULES == {
        path.name for path in THEME_PACKAGE.glob("*.py")
    }
    for name in IMPLEMENTATION_MODULES:
        source = (THEME_PACKAGE / name).read_text(encoding="utf-8")
        assert len(source.splitlines()) < 500, name
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert node.end_lineno is not None
                assert node.end_lineno - node.lineno + 1 <= 100, (
                    name,
                    node.name,
                )


def test_decoy_modules_do_not_depend_on_higher_layers_or_service_locators():
    forbidden_imports = {
        "hydra.plugins",
        "hydra.services",
        "hydra.ui",
    }
    for path in (FACADE, *THEME_PACKAGE.glob("*.py")):
        imports = _imports(path)
        assert not {
            imported
            for imported in imports
            if any(
                imported == prefix or imported.startswith(f"{prefix}.")
                for prefix in forbidden_imports
            )
        }, path

        source = path.read_text(encoding="utf-8")
        assert "DEFAULT_INVOKER" not in source, path
        assert "production_application" not in source, path
