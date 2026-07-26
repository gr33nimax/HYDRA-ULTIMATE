from __future__ import annotations

import ast
from pathlib import Path

from hydra.plugins.telemt import telemt_fallback as fallback
from hydra.plugins.telemt.telemt_fallback_model import FallbackConfig
from hydra.plugins.telemt.telemt_fallback_runtime import render_middle_proxy_mode


ROOT = Path(__file__).resolve().parents[1]
TELEMT = ROOT / "hydra" / "plugins" / "telemt"
MODULES = {
    "model": TELEMT / "telemt_fallback_model.py",
    "probe": TELEMT / "telemt_fallback_probe.py",
    "runtime": TELEMT / "telemt_fallback_runtime.py",
    "orchestrator": TELEMT / "telemt_fallback_orchestrator.py",
    "console": TELEMT / "telemt_fallback_console.py",
    "selftest": TELEMT / "telemt_fallback_selftest.py",
    "facade": TELEMT / "telemt_fallback.py",
}


def _local_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    result: set[str] = set()
    prefix = "hydra.plugins.telemt.telemt_fallback_"
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.module.startswith(prefix):
            result.add(node.module.removeprefix(prefix))
    return result


def test_fallback_split_has_one_way_dependencies_and_a_thin_facade() -> None:
    dependencies = {
        name: _local_imports(path)
        for name, path in MODULES.items()
    }
    assert dependencies["model"] == set()
    assert dependencies["probe"] == set()
    assert dependencies["runtime"] == set()
    assert dependencies["orchestrator"] == {"model", "probe"}
    assert dependencies["console"] == {"model", "probe"}
    assert "facade" not in set().union(*dependencies.values())

    facade_lines = MODULES["facade"].read_text(encoding="utf-8").splitlines()
    assert len(facade_lines) <= 320
    for name, path in MODULES.items():
        if name == "facade":
            continue
        assert len(path.read_text(encoding="utf-8").splitlines()) <= 330


def test_compatibility_facade_keeps_supported_and_test_seams() -> None:
    expected = {
        "FallbackConfig",
        "MiddleProxyProbe",
        "FallbackOrchestrator",
        "fetch_live_me_endpoints",
        "diagnostic_probe",
        "middle_proxy_quorum",
        "read_fallback_config",
        "read_runtime_middle_proxy",
        "append_fallback_section",
        "check_journal_for_me_failures",
        "set_runtime_middle_proxy",
        "apply_telemt_reload",
        "run_post_install_fallback_check",
        "me_probe_menu",
        "fallback_status_line",
        "_diagnostic_probe",
        "_patch_config_middle_proxy",
        "_reload_telemt",
        "_restart_telemt",
        "_log_fb",
    }
    assert not (expected - set(vars(fallback)))


def test_config_codec_and_runtime_renderer_preserve_other_sections(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / "telemt.toml"
    config_file.write_text(
        "[general]\n"
        "use_middle_proxy = true\n"
        "fast_mode = true\n\n"
        "[server]\n"
        "port = 8443\n",
        encoding="utf-8",
    )
    policy = FallbackConfig(
        fallback_after_attempts=8,
        fallback_after_seconds=75,
        auto_revert_to_middle=True,
    )
    fallback.append_fallback_section(config_file, policy)
    parsed = fallback.read_fallback_config(config_file)
    assert parsed == policy
    assert "[server]\nport = 8443" in config_file.read_text(encoding="utf-8")

    direct = render_middle_proxy_mode(
        config_file.read_text(encoding="utf-8"),
        enable=False,
    )
    assert "use_middle_proxy = false" in direct
    assert direct.count("[dc_overrides]") == 1
    middle = render_middle_proxy_mode(direct, enable=True)
    assert "use_middle_proxy = true" in middle
    assert "[dc_overrides]" not in middle
    assert "[server]\nport = 8443" in middle


def test_reload_wrapper_resolves_private_patch_seams_at_call_time(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        fallback,
        "_reload_telemt",
        lambda service: calls.append(("reload", service)) or False,
    )
    monkeypatch.setattr(
        fallback,
        "_restart_telemt",
        lambda service: calls.append(("restart", service)) or True,
    )
    monkeypatch.setattr(
        fallback,
        "_log_fb",
        lambda message, level="INFO": calls.append((level, message)),
    )

    assert fallback.apply_telemt_reload("telemt-test") == (True, "restart")
    assert calls[0] == ("reload", "telemt-test")
    assert ("restart", "telemt-test") in calls


def test_orchestrator_resolves_facade_side_effect_seams(
    monkeypatch,
    tmp_path: Path,
) -> None:
    effects: list[tuple[str, object]] = []

    class FailedProbe:
        def probe_all(self) -> tuple[int, int]:
            return 0, 1

    monkeypatch.setattr(
        fallback,
        "check_journal_for_me_failures",
        lambda: [],
    )
    monkeypatch.setattr(
        fallback,
        "_patch_config_middle_proxy",
        lambda path, enable: effects.append(("patch", enable)) or True,
    )
    monkeypatch.setattr(
        fallback,
        "_reload_telemt",
        lambda service: effects.append(("reload", service)) or True,
    )
    monkeypatch.setattr(fallback, "_log_fb", lambda *_args, **_kwargs: None)

    orchestrator = fallback.FallbackOrchestrator(
        FallbackConfig(
            fallback_after_attempts=1,
            fallback_after_seconds=10,
        ),
        config_file=tmp_path / "telemt.toml",
        service="telemt-test",
        probe=FailedProbe(),
    )
    result = orchestrator.run_with_fallback()

    assert orchestrator.fallback_active
    assert "Direct Mode" in result
    assert effects == [("patch", False), ("reload", "telemt-test")]


def test_diagnostic_probe_resolves_fetch_and_class_seams(monkeypatch) -> None:
    captured: list[tuple[object, ...]] = []
    marker = object()
    monkeypatch.setattr(
        fallback,
        "fetch_live_me_endpoints",
        lambda: [("203.0.113.1", 8888)],
    )
    monkeypatch.setattr(
        fallback,
        "MiddleProxyProbe",
        lambda *args: captured.append(args) or marker,
    )

    assert fallback._diagnostic_probe(1.25, 0.5) is marker
    assert captured == [([("203.0.113.1", 8888)], 1.25, 0.5)]
