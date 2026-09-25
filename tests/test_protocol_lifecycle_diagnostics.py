"""Operator-visible diagnostics and preflights for mtproto.zig."""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.executor import PluginExecutor
from hydra.plugins.mtproto_zig import runtime as zig_runtime
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.plugins.invoker import PluginInvoker
from hydra.services.plugin_lifecycle import PluginLifecycleOperations


class _Host:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, args, **_kwargs):
        self.commands.append(list(args))
        return CompletedProcess(args, 0, "active\n", "")

    def atomic_write(self, path: Path, content, **_kwargs) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else bytes(content).decode()
        path.write_text(text, encoding="utf-8")

    def ensure_directory(self, path: Path, **_kwargs) -> None:
        path.mkdir(parents=True, exist_ok=True)


def test_mtproto_apply_never_calls_an_undocumented_config_flag(tmp_path):
    host = _Host()
    config = tmp_path / "config.toml"
    binary = tmp_path / "mtproto-zig"
    binary.write_bytes(b"\x7fELF")

    assert zig_runtime.apply(
        "[server]\nport = 443\n",
        host=host,
        config_file=config,
        work_dir=tmp_path / "work",
        service="mtproto-zig",
        binary=binary,
    )

    assert ["systemctl", "is-active", "mtproto-zig"] in host.commands
    assert not any("--check-config" in command for command in host.commands)
    assert not any(str(binary) in command for command in host.commands)


def test_mtproto_install_reports_the_failed_stage():
    plugin = MtprotoZigPlugin()

    def failed_download(**kwargs) -> bool:
        kwargs["on_failure"]("не удалось скачать релизный архив mtproto.zig")
        return False

    with patch(
        "hydra.plugins.mtproto_zig.plugin.installation.download_binary",
        side_effect=failed_download,
    ):
        assert plugin.install() is False

    assert plugin.install_failure() == "не удалось скачать релизный архив mtproto.zig"


def test_lifecycle_surfaces_the_plugin_install_stage():
    errors: list[str] = []
    plugin = SimpleNamespace(
        install_failure=lambda: "не удалось скачать бинарник mtproto.zig",
    )
    operations = PluginLifecycleOperations(
        get_plugin=lambda _name: plugin,
        get_protocol=lambda state, name: state.protocols.setdefault(name, PluginState()),
        lifecycle_result=lambda _plugin, _operation, _state=None: False,
        apply_config=lambda _state: True,
        save_state=lambda _state: None,
        last_apply_error=lambda: "",
        set_apply_error=errors.append,
        log_rollback_error=lambda _message: None,
        invoker=PluginInvoker(),
    )

    assert operations.install(AppState(), "mtproto_zig") is False
    assert errors == ["Установка mtproto_zig: не удалось скачать бинарник mtproto.zig"]


class _ScriptedHost(_Host):
    """Host double that fails exactly the commands a test names."""

    def __init__(self, fail, output: str = "", stderr: str = "") -> None:
        super().__init__()
        self._fail = fail
        self._output = output
        self._stderr = stderr

    def run(self, args, **_kwargs):
        self.commands.append(list(args))
        code = 1 if self._fail(list(args)) else 0
        return CompletedProcess(args, code, self._output, self._stderr)

    def remove_file(self, path: Path) -> None:
        path.unlink(missing_ok=True)


def test_mtproto_apply_reports_an_inactive_service(tmp_path, monkeypatch):
    monkeypatch.setattr(zig_runtime, "READY_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(zig_runtime, "READY_POLLS", 2)

    stages: list[str] = []
    applied = zig_runtime.apply(
        "[server]\nport = 443\n",
        host=_ScriptedHost(lambda command: command[:2] == ["systemctl", "is-active"], output="inactive\n"),
        config_file=tmp_path / "config.toml",
        work_dir=tmp_path / "work",
        service="mtproto-zig",
        binary=tmp_path / "mtproto-zig",
        on_failure=stages.append,
    )

    assert applied is False
    assert stages == [
        "служба mtproto-zig не запустилась (state=inactive): смотрите journalctl -u mtproto-zig",
    ]


def test_mtproto_health_names_the_unit_state():
    plugin = MtprotoZigPlugin()
    with patch.object(
        MtprotoZigPlugin,
        "status",
        return_value=SimpleNamespace(running=False, info={"state": "failed"}),
    ):
        health = plugin.healthcheck_for_state(AppState())

    assert health.healthy is False
    assert health.detail == "служба mtproto-zig не активна (state=failed): смотрите journalctl -u mtproto-zig"


def _lifecycle(plugin, *, apply_config, errors: list[str]) -> PluginLifecycleOperations:
    current = {"error": ""}

    def set_error(message: str) -> None:
        current["error"] = message
        errors.append(message)

    return PluginLifecycleOperations(
        get_plugin=lambda _name: plugin,
        get_protocol=lambda state, name: state.protocols.setdefault(name, PluginState()),
        lifecycle_result=lambda *_args, **_kwargs: True,
        apply_config=apply_config,
        save_state=lambda _state: None,
        last_apply_error=lambda: current["error"],
        set_apply_error=set_error,
        log_rollback_error=lambda _message: None,
        invoker=PluginInvoker(),
    )


def test_bounded_reason_redacts_and_bounds_command_output():
    from hydra.utils.commands import bounded_reason

    reason = bounded_reason(
        SimpleNamespace(stderr="\n  Failed to reload daemon: token=abcd1234 leaked  \nsecond\n"),
        limit=40,
    )

    assert reason.startswith("Failed to reload daemon:")
    assert "abcd1234" not in reason
    assert "<redacted" not in reason, "a half-written marker must never be reported"
    assert len(reason) <= 40

    full = bounded_reason(SimpleNamespace(stderr="denied token=abcd1234\n"))
    assert full == "denied token=<redacted>"
    assert bounded_reason(SimpleNamespace(stderr=b"boom\n")) == "boom"
    assert bounded_reason(SimpleNamespace(stderr="")) == ""


def test_mtproto_apply_reports_the_service_reason(tmp_path):
    stages: list[str] = []
    applied = zig_runtime.apply(
        "[server]\nport = 443\n",
        host=_ScriptedHost(
            lambda command: command[:2] == ["systemctl", "is-active"],
            output="inactive\n",
            stderr="Failed to start mtproto-zig.service: exit code\n",
        ),
        config_file=tmp_path / "config.toml",
        work_dir=tmp_path / "work",
        service="mtproto-zig",
        binary=tmp_path / "mtproto-zig",
        on_failure=stages.append,
    )

    assert applied is False
    assert stages == [
        "служба mtproto-zig не запустилась (state=inactive): смотрите journalctl -u mtproto-zig "
        "(Failed to start mtproto-zig.service: exit code)",
    ]


def test_lifecycle_prefers_the_plugin_apply_stage():
    errors: list[str] = []
    plugin = SimpleNamespace(
        apply_failure=lambda: "служба mtproto-zig не запустилась: смотрите journalctl -u mtproto-zig",
    )

    enabled = _lifecycle(plugin, apply_config=lambda _state: False, errors=errors).enable(
        AppState(),
        "mtproto_zig",
    )

    assert enabled is False
    assert errors[-1] == "Применение mtproto_zig: служба mtproto-zig не запустилась: смотрите journalctl -u mtproto-zig"


def test_lifecycle_never_reports_an_empty_failure_message():
    errors: list[str] = []

    enabled = _lifecycle(
        SimpleNamespace(),
        apply_config=lambda _state: False,
        errors=errors,
    ).enable(AppState(), "mtproto_zig")

    assert enabled is False
    assert errors[-1] == "Включение mtproto_zig не удалось"


def _false_apply_plugin(**overrides):
    """A plugin whose apply returns false, optionally recording its own stage."""
    plugin = SimpleNamespace(
        meta=SimpleNamespace(name="mtproto_zig", contract_version=1),
        snapshot=lambda state: {},
        apply=lambda state: False,
        rollback=lambda state, snapshot: True,
    )
    for name, value in overrides.items():
        setattr(plugin, name, value)
    return plugin


def _apply_enabled_error(plugin) -> str:
    """Run the canonical apply path and return the message it raises."""
    state = AppState(protocols={"mtproto_zig": PluginState(enabled=True)})
    try:
        PluginExecutor(PluginCatalog([plugin])).apply_enabled(
            state,
            log_error=lambda _message: None,
        )
    except RuntimeError as exc:
        return str(exc)
    raise AssertionError("a false plugin apply must raise")


def test_executor_prefers_the_plugin_apply_stage_over_the_generic_text():
    plugin = _false_apply_plugin(
        apply_failure=lambda: "WEB-мост не подтверждён: no route",
    )

    message = _apply_enabled_error(plugin)

    assert message == ("Plugin mtproto_zig apply returned false: WEB-мост не подтверждён: no route")


def test_executor_keeps_the_generic_text_without_a_plugin_stage():
    assert _apply_enabled_error(_false_apply_plugin()) == ("Plugin mtproto_zig apply returned false")


def test_a_raising_apply_failure_reader_never_breaks_the_rollback():
    rolled_back: list[str] = []

    def broken_reader() -> str:
        raise RuntimeError("diagnostics unavailable")

    plugin = _false_apply_plugin(
        apply_failure=broken_reader,
        rollback=lambda state, snapshot: rolled_back.append("rollback") or True,
    )

    assert _apply_enabled_error(plugin) == "Plugin mtproto_zig apply returned false"
    assert rolled_back == ["rollback"]


def test_a_non_string_apply_failure_reader_keeps_the_generic_text():
    plugin = _false_apply_plugin(apply_failure=lambda: Mock())

    assert _apply_enabled_error(plugin) == "Plugin mtproto_zig apply returned false"


def _raising_stage_reader():
    raise RuntimeError("diagnostics unavailable")


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"apply_failure": lambda: "  WEB-мост не подтверждён: no route  "}, "WEB-мост не подтверждён: no route"),
        ({}, ""),
        ({"apply_failure": _raising_stage_reader}, ""),
        ({"apply_failure": lambda: Mock()}, ""),
    ],
)
def test_executor_and_lifecycle_read_the_same_plugin_stage(overrides, expected):
    """One canonical reader: the two call sites must never drift apart."""
    plugin = _false_apply_plugin(**overrides)

    message = _apply_enabled_error(plugin)
    executor_stage = message.split(": ", 1)[1] if ": " in message else ""

    assert PluginLifecycleOperations._plugin_stage(plugin, "apply") == expected
    assert executor_stage == expected


def test_the_stage_reader_serves_both_install_and_apply_hooks():
    plugin = SimpleNamespace(
        install_failure=lambda: "  шаг установки  ",
        apply_failure=lambda: "шаг применения",
    )

    assert PluginLifecycleOperations._plugin_stage(plugin, "install") == "шаг установки"
    assert PluginLifecycleOperations._plugin_stage(plugin, "apply") == "шаг применения"
