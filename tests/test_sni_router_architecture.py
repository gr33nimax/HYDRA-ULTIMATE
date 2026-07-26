"""Architecture guards for the decomposed SNI-router composition root."""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

from hydra.core import sni_router
from hydra.core.state import AppState


ROOT = Path(__file__).parents[1]
SNI_MODULES = {
    "sni_router.py",
    "sni_router_audit.py",
    "sni_router_install.py",
    "sni_router_planning.py",
    "sni_router_document.py",
    "sni_router_http.py",
    "sni_router_reconcile.py",
    "sni_router_runtime.py",
    "sni_router_runtime_models.py",
    "sni_router_units.py",
}


def _tree(name: str) -> ast.Module:
    path = ROOT / "hydra" / "core" / name
    return ast.parse(path.read_text(encoding="utf-8"))


def _imports(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            modules.update(
                f"{node.module}.{alias.name}"
                for alias in node.names
            )
    return modules


def test_sni_router_modules_are_cohesive_and_bounded() -> None:
    core = ROOT / "hydra" / "core"
    assert {path.name for path in core.glob("sni_router*.py")} == SNI_MODULES
    for name in SNI_MODULES:
        path = core / name
        assert path.is_file()
        source = path.read_text(encoding="utf-8")
        assert len(source.splitlines()) <= 500, name
        functions = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        assert all(
            node.end_lineno - node.lineno + 1 <= 120
            for node in functions
        ), name

    facade = _tree("sni_router.py")
    functions = [
        node
        for node in facade.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    assert max(node.end_lineno - node.lineno + 1 for node in functions) <= 25


def test_sni_router_facade_uses_every_extracted_role() -> None:
    facade = _tree("sni_router.py")
    imported_roles = {
        alias.name
        for node in facade.body
        if isinstance(node, ast.ImportFrom) and node.module == "hydra.core"
        for alias in node.names
        if alias.name.startswith("sni_router_")
    }
    assert imported_roles == {
        "sni_router_audit",
        "sni_router_install",
        "sni_router_planning",
        "sni_router_document",
        "sni_router_runtime",
        "sni_router_units",
    }

    forbidden_host_implementation = {
        "base64",
        "json",
        "os",
        "shutil",
        "subprocess",
        "tempfile",
    }
    assert not (_imports(facade) & forbidden_host_implementation)


def test_pure_sni_policy_and_rendering_do_not_import_host_infrastructure() -> None:
    forbidden = {
        "hydra.core.host",
        "os",
        "pathlib",
        "shutil",
        "subprocess",
        "tempfile",
        "urllib",
        "urllib.request",
    }
    for name in (
        "sni_router_planning.py",
        "sni_router_document.py",
        "sni_router_http.py",
    ):
        assert not (_imports(_tree(name)) & forbidden), name

    for name in SNI_MODULES - {"sni_router.py"}:
        assert "hydra.core.sni_router" not in _imports(_tree(name)), name


def test_planning_facade_delegates_with_current_port_policy() -> None:
    state = AppState()
    with patch.object(
        sni_router._planning,
        "needs_mux",
        return_value=True,
    ) as delegate:
        assert sni_router.needs_mux(state) is True
    delegate.assert_called_once_with(state, sni_router._INTERNAL_PORTS)


def test_rendering_facade_passes_dynamic_settings_and_patchable_callbacks() -> None:
    state = AppState()
    rendered = {"sentinel": True}
    with (
        patch.object(
            sni_router._rendering,
            "generate_config",
            return_value=rendered,
        ) as delegate,
        patch.object(sni_router, "SOURCE_PRESERVATION_ENABLED", True),
    ):
        assert sni_router._generate_config([], state) is rendered

    _backends, _state, settings = delegate.call_args.args
    assert settings.source_preservation_enabled is True
    assert settings.internal_ports is sni_router._INTERNAL_PORTS
    assert delegate.call_args.kwargs["quic_owner"] is sni_router.get_quic_owner
    assert delegate.call_args.kwargs["proxy_factory"] is sni_router._proxy_handler


def test_runtime_facade_resolves_legacy_patch_seams_at_call_time() -> None:
    state = AppState()
    replacement = lambda **_kwargs: True
    with (
        patch.object(
            sni_router._runtime,
            "rebuild",
            return_value=True,
        ) as delegate,
        patch.object(sni_router, "_install_service", replacement),
    ):
        assert sni_router.rebuild(state) is True

    operations = delegate.call_args.args[3]
    assert operations.install_caddy_service is replacement
    assert operations.generate_config is sni_router._generate_config
    assert operations.collect_backends is sni_router._collect_backends


def test_runtime_reconciliation_layers_form_a_one_way_dag() -> None:
    imports = {
        name: _imports(_tree(name))
        for name in (
            "sni_router_runtime_models.py",
            "sni_router_reconcile.py",
            "sni_router_runtime.py",
        )
    }
    assert "hydra.core.sni_router_reconcile" not in imports[
        "sni_router_runtime_models.py"
    ]
    assert "hydra.core.sni_router_runtime" not in imports[
        "sni_router_runtime_models.py"
    ]
    assert "hydra.core.sni_router_runtime" not in imports[
        "sni_router_reconcile.py"
    ]
    for name in imports:
        assert "hydra.core.sni_router" not in imports[name]
    assert "hydra.core.sni_router_runtime_models" in imports[
        "sni_router_reconcile.py"
    ]
    assert "hydra.core.sni_router_reconcile" in imports[
        "sni_router_runtime.py"
    ]
    assert "hydra.core.sni_router_runtime_models" in imports[
        "sni_router_runtime.py"
    ]
