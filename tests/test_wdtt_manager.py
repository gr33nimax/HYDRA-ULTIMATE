from subprocess import CompletedProcess, TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.plugins.wdtt import manager


def test_diagnostic_output_times_out_instead_of_freezing():
    admin = MagicMock()
    admin.run_command.side_effect = TimeoutExpired(["systemctl"], 5)
    app = SimpleNamespace(admin=admin)

    output = manager._diagnostic_output(
        app,
        ["systemctl", "status", "wdtt"],
        "Нет вывода",
    )

    assert "не ответила за 5 сек" in output


def test_status_logs_disable_pagers_and_always_offer_return():
    results = [
        CompletedProcess([], 0, stdout="active", stderr=""),
        CompletedProcess([], 0, stdout="log line", stderr=""),
    ]
    admin = MagicMock()
    admin.run_command.side_effect = results
    app = SimpleNamespace(admin=admin)
    with (
        patch.object(manager, "clear"),
        patch.object(manager, "title"),
        patch.object(manager, "prompt") as prompt,
    ):
        manager._show_status_logs(app)

    status_command = admin.run_command.call_args_list[0].args[0]
    journal_command = admin.run_command.call_args_list[1].args[0]
    assert "--no-pager" in status_command
    assert "--no-pager" in journal_command
    assert admin.run_command.call_args_list[0].kwargs["timeout"] == 5
    assert admin.run_command.call_args_list[1].kwargs["timeout"] == 5
    prompt.assert_called_once_with("Нажмите Enter, чтобы вернуться")
