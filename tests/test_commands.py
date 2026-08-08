from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from hydra.utils.commands import CommandError, redact_command, redact_text, run


def test_run_uses_argv_timeout_and_no_shell():
    completed = MagicMock(returncode=0)
    with patch("hydra.utils.commands.subprocess.run", return_value=completed) as invoked:
        assert run(["systemctl", "is-active", "demo"], timeout=7) is completed
    invoked.assert_called_once_with(
        ["systemctl", "is-active", "demo"],
        input=None,
        capture_output=True,
        text=False,
        timeout=7,
        env=None,
        check=False,
    )


def test_run_converts_timeout_to_domain_error():
    with patch(
        "hydra.utils.commands.subprocess.run",
        side_effect=subprocess.TimeoutExpired(["tool"], 3),
    ):
        with pytest.raises(CommandError, match="timed out"):
            run(["tool"], timeout=3)


def test_command_redaction_masks_inline_secrets():
    rendered = redact_command(["tool", "--token=value", "password=hunter2"])
    assert "value" not in rendered
    assert "hunter2" not in rendered
    assert "<redacted>" in rendered


def test_log_redaction_masks_vk_call_and_qwdtt_shared_links():
    rendered = redact_text(
        "created https://vk.com/call/join/shared-room qwdtt://config?pass=secret",
    )
    assert "shared-room" not in rendered
    assert "config?" not in rendered
    assert rendered == (
        "created https://vk.com/call/join/<redacted> qwdtt://<redacted>"
    )


def test_log_redaction_masks_extended_vk_token_and_ru_host():
    rendered = redact_text("created https://vk.ru/call/join/shared+room==")

    assert "shared+room" not in rendered
    assert rendered == "created https://vk.com/call/join/<redacted>"
