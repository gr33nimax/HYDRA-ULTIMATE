"""Architecture guards for the state schema, migrations, and storage adapter."""
from __future__ import annotations

import ast
from pathlib import Path

from hydra.core import state
from hydra.core import state_models


ROOT = Path(__file__).parents[1]
CORE = ROOT / "hydra" / "core"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_state_schema_and_migrations_are_infrastructure_free() -> None:
    forbidden_roots = {
        "fcntl",
        "json",
        "msvcrt",
        "os",
        "pathlib",
        "shutil",
        "threading",
    }
    violations: list[str] = []
    for name in ("state_models.py", "state_migrations.py"):
        for node in ast.walk(_tree(CORE / name)):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module.split(".", 1)[0] in forbidden_roots:
                    violations.append(f"{name}:{node.lineno} {module}")
    assert violations == []


def test_state_storage_facade_reexports_the_pure_schema() -> None:
    assert state.AppState is state_models.AppState
    assert state.PluginState is state_models.PluginState
    assert state.User is state_models.User
    assert state.validate_state is state_models.validate_state
    assert state.persist_state_migration is state.migrate_persisted_state

    assert len((CORE / "state.py").read_text(encoding="utf-8").splitlines()) < 400
    assert (
        len(
            (CORE / "state_models.py")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        < 240
    )
    assert (
        len(
            (CORE / "state_migrations.py")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        < 140
    )


def test_state_storage_imports_never_smuggle_domain_types() -> None:
    storage_symbols = {
        "STATE_DIR",
        "STATE_FILE",
        "_validate_raw_state",
        "load_state",
        "migrate_persisted_state",
        "persist_state_migration",
        "restore_desired_state",
        "save_state",
        "update_state",
    }
    violations: list[str] = []
    paths = [
        ROOT / "main.py",
        *sorted((ROOT / "hydra").rglob("*.py")),
    ]
    for path in paths:
        if path == CORE / "state.py":
            continue
        for node in ast.walk(_tree(path)):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "hydra.core.state"
            ):
                forbidden = {
                    alias.name
                    for alias in node.names
                    if alias.name not in storage_symbols
                }
                if forbidden:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} "
                        f"{sorted(forbidden)}"
                    )
    assert violations == []


def test_plugin_layer_never_reads_application_state_storage() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "hydra" / "plugins").rglob("*.py")):
        for node in ast.walk(_tree(path)):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            if "hydra.core.state" in modules:
                violations.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}"
                )
    assert violations == []
