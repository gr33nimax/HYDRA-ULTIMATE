from __future__ import annotations

from unittest.mock import patch

from hydra.ui import tui


def test_ask_returns_none_on_cancel_and_interrupt():
    for failure in (KeyboardInterrupt, EOFError):
        with patch("builtins.input", side_effect=failure):
            assert tui.ask("Value") is None


def test_ask_keeps_default_only_for_empty_answer():
    with patch("builtins.input", side_effect=["", "custom"]):
        assert tui.ask("Value", "default") == "default"
        assert tui.ask("Value", "default") == "custom"


def test_ask_secret_does_not_echo_and_can_be_cancelled(capsys):
    with patch("getpass.getpass", return_value="hunter2"):
        assert tui.ask_secret("SSH password") == "hunter2"
    assert "hunter2" not in capsys.readouterr().out

    with patch("getpass.getpass", side_effect=KeyboardInterrupt):
        assert tui.ask_secret("SSH password") is None


def test_prompt_preserves_default_for_existing_callers():
    with patch("builtins.input", return_value=""):
        assert tui.prompt("Value", "default") == "default"


def test_menu_maps_cancel_to_back_key():
    for failure in (KeyboardInterrupt, EOFError):
        with patch("builtins.input", side_effect=failure):
            assert tui.menu([("1", "Next", ""), ("0", "Back", "")]) == "0"


def test_menu_renders_each_description_line(capsys):
    with patch("builtins.input", return_value="0"):
        tui.menu([("1", "Node", ["node.example", "healthy; checked 2 minutes ago"]), ("0", "Back", "")])
    output = capsys.readouterr().out
    assert "node.example" in output
    assert "healthy; checked 2 minutes ago" in output


def test_menu_accepts_numeric_keys_with_surrounding_whitespace():
    with patch("builtins.input", return_value=" 1 "):
        assert tui.menu([("1", "Next", ""), ("0", "Back", "")]) == "1"


def test_menu_never_invents_a_choice_for_unknown_input():
    with patch("builtins.input", return_value="42"):
        assert tui.menu([("1", "Next", ""), ("0", "Back", "")]) == "42"
