"""Operator-visible diagnostics and preflights for Telemt and mtproto.zig."""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hydra.core.state import AppState, PluginState
from hydra.plugins.mtproto_zig import runtime as zig_runtime
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.plugins.telemt.plugin import TelemtPlugin
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


def test_mtproto_apply_never_calls_an_undocumented_config_flag(tmp_path):
    host = _Host()
    config = tmp_path / "config.toml"
    binary = tmp_path / "mtproto-zig"
    binary.write_bytes(b"\x7fELF")

    assert zig_runtime.apply(
        "[server]\nport = 443\n",
        host=host,
        config_file=config,
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


def test_telemt_plugin_forwards_the_installer_stage():
    plugin = TelemtPlugin()

    with patch("hydra.plugins.telemt.plugin.installation.install", return_value=False) as install:
        assert plugin.install() is False

    on_failure = install.call_args.kwargs["on_failure"]
    on_failure("не удалось скачать бинарник Telemt")

    assert plugin.install_failure() == "не удалось скачать бинарник Telemt"


def test_lifecycle_surfaces_the_plugin_install_stage():
    errors: list[str] = []
    plugin = SimpleNamespace(
        install_failure=lambda: "не удалось скачать бинарник Telemt",
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

    assert operations.install(AppState(), "telemt") is False
    assert errors == ["Установка telemt: не удалось скачать бинарник Telemt"]


def _telemt_app(*, port_free: bool, install_ok: bool = True, apply_error: str = ""):
    return SimpleNamespace(
        diagnostics=SimpleNamespace(port_occupied=lambda _port: not port_free),
        protocols=SimpleNamespace(
            install=Mock(return_value=install_ok),
            reinstall=Mock(return_value=install_ok),
            enable=Mock(return_value=install_ok),
        ),
        admin=SimpleNamespace(save_state=Mock()),
        apply_error=lambda: apply_error,
    )


def _telemt_state(port: int = 8443, domain: str = "old.example") -> AppState:
    return AppState(
        protocols={"telemt": PluginState(config={"port": port, "tls_domain": domain})},
    )


def _run_install(state: AppState, app, *, port: int, domain: str) -> list[str]:
    from hydra.ui.plugin_managers import _telemt_operations
    from hydra.ui.plugin_managers import telemt
    from hydra.ui.plugin_managers._facade_bridge import bind_facade

    errors: list[str] = []
    with (
        bind_facade(telemt),
        patch.object(telemt, "clear"),
        patch.object(telemt, "warn"),
        patch.object(telemt, "success"),
        patch.object(telemt, "_pause"),
        patch.object(telemt, "error", errors.append),
        patch.object(telemt, "_ask", return_value=domain),
        patch.object(telemt, "confirm", return_value=True),
        patch("hydra.ui.plugin_managers._telemt_operations._choose_port", return_value=port),
    ):
        _telemt_operations.run_install(state, app)
    return errors


def test_telemt_install_refuses_a_port_owned_by_another_service():
    app = _telemt_app(port_free=False)

    errors = _run_install(_telemt_state(), app, port=9443, domain="new.example")

    assert errors == ["Порт 9443 уже занят другим сервисом. Выберите свободный порт."]
    app.admin.save_state.assert_not_called()
    app.protocols.install.assert_not_called()


def test_telemt_reconfigure_keeps_the_port_it_already_listens_on():
    app = _telemt_app(port_free=False)

    errors = _run_install(_telemt_state(port=8443), app, port=8443, domain="new.example")

    assert errors == []
    app.admin.save_state.assert_called()
    app.protocols.enable.assert_called_once()


def test_telemt_install_failure_shows_the_plugin_stage():
    app = _telemt_app(
        port_free=True,
        install_ok=False,
        apply_error="Установка telemt: не удалось скачать бинарник Telemt",
    )

    errors = _run_install(_telemt_state(), app, port=9443, domain="new.example")

    assert errors == [
        "Установка Telemt не удалась: Установка telemt: не удалось скачать бинарник Telemt",
    ]


def test_telemt_menu_hides_actions_until_it_is_installed():
    from hydra.ui.plugin_managers import _telemt_menu
    from hydra.ui.plugin_managers import telemt
    from hydra.ui.plugin_managers._facade_bridge import bind_facade

    with bind_facade(telemt):
        uninstalled = [key for key, _label, _hint in _telemt_menu._menu_options(installed=False, enabled=False)]
        installed = [key for key, _label, _hint in _telemt_menu._menu_options(installed=True, enabled=False)]

    assert uninstalled == ["1", "-", "0"]
    assert {"2", "3", "4", "5", "6", "7", "9"} <= set(installed)


def test_telemt_dispatch_requires_installation_for_other_actions():
    from hydra.ui.plugin_managers import _telemt_menu
    from hydra.ui.plugin_managers import telemt
    from hydra.ui.plugin_managers._facade_bridge import bind_facade

    warnings: list[str] = []
    with (
        bind_facade(telemt),
        patch.object(telemt, "warn", warnings.append),
        patch.object(telemt, "_pause"),
    ):
        keep_open = _telemt_menu._dispatch(
            "5",
            AppState(),
            SimpleNamespace(),
            SimpleNamespace(enabled=False),
            installed=False,
        )

    assert keep_open is True
    assert warnings == ["Сначала установите Telemt."]
