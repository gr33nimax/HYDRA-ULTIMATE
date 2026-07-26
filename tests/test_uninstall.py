import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from hydra.core.state import AppState
from hydra.core.uninstall import uninstall_hydra, uninstall_plan
from hydra.services.uninstall import CleanupStep, UninstallService


def test_uninstall_dry_run_is_side_effect_free():
    state = AppState()
    result = uninstall_hydra(
        state,
        confirmed=False,
        dry_run=True,
        keep_data=False,
    )
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert any(path.replace("\\", "/").endswith("/var/lib/hydra") for path in result["paths"])


def test_uninstall_requires_explicit_confirmation():
    with pytest.raises(ValueError, match="--yes"):
        uninstall_hydra(AppState(), confirmed=False)


def test_keep_data_removes_data_paths_from_plan():
    plan = uninstall_plan(AppState(), keep_data=True)
    normalized = [path.replace("\\", "/") for path in plan["paths"]]
    assert not any(path.endswith("/var/lib/hydra") for path in normalized)
    assert not any(path.endswith("/var/log/hydra") for path in normalized)


class _Plugin:
    def __init__(
        self,
        name: str,
        events: list[str],
        *,
        result: bool = True,
        failure: Exception | None = None,
    ) -> None:
        self.meta = SimpleNamespace(name=name, contract_version=1)
        self.events = events
        self.result = result
        self.failure = failure

    def uninstall(self) -> bool:
        self.events.append(f"plugin:{self.meta.name}")
        if self.failure is not None:
            raise self.failure
        return self.result


def test_uninstall_service_preserves_cleanup_order_and_failure_semantics():
    events: list[str] = []
    plugins = (
        _Plugin("first", events),
        _Plugin("second", events, result=False),
        _Plugin("third", events, failure=RuntimeError("broken")),
    )
    finalized: dict = {}

    def fail_auxiliary_cleanup() -> None:
        events.append("cleanup:ios")
        raise RuntimeError("rules remain")

    def clean_auxiliary_rules() -> None:
        events.append("cleanup:syn")

    def finalize(state, **options):
        finalized.update(options)
        failures = list(options["initial_failures"])
        return {
            "ok": not failures,
            "dry_run": False,
            "removed": uninstall_plan(
                state,
                keep_data=options["keep_data"],
                plugin_names=options["plugin_names"],
            ),
            "failures": failures,
        }

    service = UninstallService(
        plugin_inventory=lambda: plugins,
        cleanup_steps=(
            CleanupStep("telemt-ios", fail_auxiliary_cleanup),
            CleanupStep("telemt-syn", clean_auxiliary_rules),
        ),
        remove_installation=finalize,
    )

    result = service.uninstall(
        AppState(),
        confirmed=True,
        keep_data=True,
    )

    assert events == [
        "cleanup:ios",
        "cleanup:syn",
        "plugin:third",
        "plugin:second",
        "plugin:first",
    ]
    assert finalized["plugin_names"] == ["third", "second", "first"]
    assert result["failures"] == [
        "telemt-ios: rules remain",
        "plugin third: broken",
        "plugin second: returned false",
    ]
    assert result["removed"]["keep_data"] is True
    assert result["ok"] is False


def test_uninstall_service_dry_run_and_confirmation_are_side_effect_free():
    events: list[str] = []
    plugin = _Plugin("transport", events)
    service = UninstallService(
        plugin_inventory=lambda: [plugin],
        cleanup_steps=(
            CleanupStep("auxiliary", lambda: events.append("cleanup")),
        ),
        remove_installation=lambda *args, **kwargs: pytest.fail(
            "host removal must not run",
        ),
    )

    result = service.uninstall(
        AppState(),
        confirmed=False,
        dry_run=True,
    )
    assert result["plugins"] == ["transport"]
    assert events == []

    with pytest.raises(ValueError, match="--yes"):
        service.uninstall(AppState(), confirmed=False)
    assert events == []


def test_core_uninstall_has_no_upward_or_concrete_plugin_dependencies():
    root = Path(__file__).parents[1]
    path = root / "hydra" / "core" / "uninstall.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)

    assert not any(
        module.startswith(("hydra.plugins", "hydra.services"))
        for module in imports
    )
    assert "registry" not in source
    assert "telemt_ios_fix" not in source
    assert "telemt_syn_limiter" not in source


def test_cli_uninstall_routes_through_application_boundary():
    root = Path(__file__).parents[1]
    source = (root / "hydra" / "cli_dispatch.py").read_text(encoding="utf-8")

    assert "app.uninstall(" in source
    assert "from hydra.core.uninstall import" not in source
