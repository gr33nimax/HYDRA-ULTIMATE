"""Node input primitives: a cancel must never look like a value.

``prompt`` returns its default on Ctrl-C and EOF, which is fine for menus that only
read a free-form string but wrong for a form that would then save the default. The node
screens use ``ask``/``ask_secret``, which distinguish "the operator refused" from "the
operator accepted the default", and a test here keeps the old behaviour of ``prompt``
for every other caller.
"""

from __future__ import annotations

import builtins

import pytest

from hydra.ui import tui


def test_ask_returns_none_on_cancel_and_interrupt(monkeypatch):
    for signal in (KeyboardInterrupt, EOFError):
        monkeypatch.setattr(builtins, "input", lambda *_a, _s=signal: (_ for _ in ()).throw(_s()))
        assert tui.ask("Имя", "прежнее") is None


def test_ask_keeps_the_default_only_on_an_empty_answer(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a: "")
    assert tui.ask("Имя", "прежнее") == "прежнее"
    monkeypatch.setattr(builtins, "input", lambda *_a: "  новое  ")
    assert tui.ask("Имя", "прежнее") == "новое"


def test_ask_secret_reads_without_echo_and_can_be_cancelled(monkeypatch):
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda *_a: "hunter2")
    assert tui.ask_secret("Пароль SSH") == "hunter2"

    for signal in (KeyboardInterrupt, EOFError):
        monkeypatch.setattr(getpass, "getpass", lambda *_a, _s=signal: (_ for _ in ()).throw(_s()))
        assert tui.ask_secret("Пароль SSH") is None


def test_prompt_keeps_returning_its_default_for_existing_callers(monkeypatch):
    """Other menus rely on this; only the node forms need the stricter reading."""
    monkeypatch.setattr(builtins, "input", lambda *_a: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert tui.prompt("Вопрос", "прежнее") == "прежнее"


def test_menu_maps_cancel_to_the_back_key(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda *_a: (_ for _ in ()).throw(EOFError()))
    assert tui.menu([("1", "Раз", ""), ("0", "Назад", "")], "МЕНЮ") == "0"


def test_menu_renders_every_description_line(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda *_a: "0")
    tui.menu(
        [("2", "uk-1 · UK", ["194.147.35.112", "healthy · проверена 2 минуты назад"]), ("0", "Назад", "")],
        "НОДЫ",
    )
    output = capsys.readouterr().out
    assert "194.147.35.112" in output
    assert "healthy · проверена 2 минуты назад" in output


@pytest.mark.parametrize("key", ["1", " 1 ", "1\n"])
def test_menu_still_accepts_numeric_keys_with_surrounding_noise(monkeypatch, key):
    monkeypatch.setattr(builtins, "input", lambda *_a: key)
    assert tui.menu([("1", "Раз", ""), ("0", "Назад", "")], "МЕНЮ") == "1"


def test_menu_never_invents_a_choice_for_unknown_input(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a: "42")
    assert tui.menu([("1", "Раз", ""), ("0", "Назад", "")], "МЕНЮ") == "42"
