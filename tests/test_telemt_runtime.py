"""Transactional, Telemt-owned runtime behaviour."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import PluginStatus
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.executor import PluginExecutor
from hydra.plugins.telemt import plugin as telemt_plugin
from hydra.plugins.telemt import runtime


class _Host:
    def __init__(self, root: Path, failures: set[str] | None = None) -> None:
        self.root = root
        self.failures = failures or set()
        self.commands: list[list[str]] = []

    def ensure_directory(self, path, *, mode=0o755):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)

    def atomic_write(self, path, content, *, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content) if isinstance(content, bytes) else path.write_text(content)
        path.chmod(mode)

    def remove_file(self, path):
        path.unlink(missing_ok=True)

    def run(self, command, **_kwargs):
        self.commands.append(command)
        failed = command[1] if command[0] == "systemctl" else command[0]
        return CompletedProcess(command, int(failed in self.failures), "active\n", "")


def test_apply_mutates_only_telemt_config_and_its_unit(tmp_path):
    host = _Host(tmp_path)
    config = tmp_path / "etc" / "config.toml"

    assert runtime.apply(
        "[server]\nport = 443\n",
        host=host,
        config_file=config,
        work_dir=tmp_path / "work",
        service_name="telemt",
    )

    assert config.read_text() == "[server]\nport = 443\n"
    assert ["chown", "root:telemt", str(config)] in host.commands
    # The unit runs as the service user: its working directory and the config
    # directory must be usable by that user, otherwise systemd fails CHDIR.
    assert ["chown", "root:telemt", str(config.parent)] in host.commands
    assert ["chown", "telemt:telemt", str(tmp_path / "work")] in host.commands
    assert {command[1] for command in host.commands if command[0] == "systemctl"} == {
        "daemon-reload",
        "enable",
        "restart",
        "is-active",
    }
    # daemon-reload accepts no unit name; passing one fails with "Too many arguments."
    reloads = [command for command in host.commands if command[1] == "daemon-reload"]
    assert reloads
    assert all(len(command) == 2 for command in reloads)


def test_executor_rolls_back_telemt_when_apply_fails(tmp_path):
    config = tmp_path / "config.toml"
    service = tmp_path / "telemt.service"
    config.write_text("old", encoding="utf-8")
    service.write_text("old unit", encoding="utf-8")
    state = AppState()
    state.protocols["telemt"] = PluginState(enabled=True)
    transport = telemt_plugin.TelemtPlugin()
    transport._pending_cfg = "new"
    host = _Host(tmp_path, failures={"restart"})

    with (
        patch.object(telemt_plugin, "HOST", host),
        patch.object(telemt_plugin, "CONFIG_FILE", config),
        patch.object(telemt_plugin, "SERVICE_FILE", service),
        patch.object(TelemtPlugin := telemt_plugin.TelemtPlugin, "status", return_value=PluginStatus(True, True, True)),
        pytest.raises(RuntimeError, match="telemt apply returned false"),
    ):
        PluginExecutor(PluginCatalog([transport])).apply_enabled(state, log_error=lambda _message: None)

    assert config.read_text(encoding="utf-8") == "old"
    assert service.read_text(encoding="utf-8") == "old unit"


def test_failed_apply_can_restore_the_captured_service_state(tmp_path):
    config = tmp_path / "etc" / "config.toml"
    unit = tmp_path / "systemd" / "telemt.service"
    config.parent.mkdir(parents=True)
    unit.parent.mkdir(parents=True)
    config.write_text("old", encoding="utf-8")
    unit.write_text("old unit", encoding="utf-8")
    snapshot = runtime.snapshot(config_file=config, service_file=unit, running=True)
    host = _Host(tmp_path, failures={"restart"})

    assert not runtime.apply(
        "new",
        host=host,
        config_file=config,
        work_dir=tmp_path / "work",
        service_name="telemt",
    )
    host.failures.clear()
    assert runtime.rollback(snapshot, host=host, config_file=config, service_file=unit, service_name="telemt")

    assert config.read_text() == "old"
    assert unit.read_text() == "old unit"
    assert ["systemctl", "restart", "telemt"] == host.commands[-1]
