from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

from hydra.plugins.wdtt import manager


def test_diagnostic_output_times_out_instead_of_freezing():
    with patch.object(
        manager.subprocess,
        "run",
        side_effect=TimeoutExpired(["systemctl"], 5),
    ):
        output = manager._diagnostic_output(["systemctl", "status", "wdtt"], "Нет вывода")

    assert "не ответила за 5 сек" in output


def test_status_logs_disable_pagers_and_always_offer_return():
    results = [
        CompletedProcess([], 0, stdout="active", stderr=""),
        CompletedProcess([], 0, stdout="log line", stderr=""),
    ]
    with (
        patch.object(manager, "clear"),
        patch.object(manager, "title"),
        patch.object(manager.subprocess, "run", side_effect=results) as run,
        patch.object(manager, "prompt") as prompt,
    ):
        manager._show_status_logs()

    status_command = run.call_args_list[0].args[0]
    journal_command = run.call_args_list[1].args[0]
    assert "--no-pager" in status_command
    assert "--no-pager" in journal_command
    assert run.call_args_list[0].kwargs["timeout"] == 5
    assert run.call_args_list[1].kwargs["timeout"] == 5
    prompt.assert_called_once_with("Нажмите Enter, чтобы вернуться")
