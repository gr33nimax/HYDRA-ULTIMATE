"""Node input primitives: a cancel must never look like a value.

``prompt`` returns its default on Ctrl-C and EOF, which is fine for menus that only
read a free-form string but wrong for a form that would then save the default. The node
screens use ``ask``/``ask_secret``, which distinguish "the operator refused" from "the
operator accepted the default", and a test here keeps the old behaviour of ``prompt``
for every other caller.
"""

from __future__ import annotations

import builtins
import os
from pathlib import Path

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


def _helper_root(script: str) -> str:
    """The PYTHONPATH the helper bakes in, read back the way a shell would."""
    line = next(item for item in script.splitlines() if item.startswith("export PYTHONPATH="))
    value = line.split("=", 1)[1]
    return value.split("${PYTHONPATH", 1)[0].strip().strip("'")


def test_the_baked_package_root_makes_hydra_importable_from_anywhere(tmp_path):
    """The live failure: ssh starts the helper, and a fresh interpreter knows nothing
    about the launcher's sys.path, so the helper must carry the package root itself."""
    import os
    import subprocess
    import sys

    from hydra.services.nodes.ssh_auth import SshPasswordAuth

    with SshPasswordAuth("live password") as auth:
        environment = auth.environment(interpreter=sys.executable)
        script = Path(environment["SSH_ASKPASS"]).read_text(encoding="utf-8")
        environment["PYTHONPATH"] = _helper_root(script)
        environment.pop("SSH_ASKPASS", None)
        environment.pop("SSH_ASKPASS_REQUIRE", None)
        # A fresh interpreter, a foreign directory, and only what the helper baked in.
        result = subprocess.run(
            [sys.executable, "-m", "hydra.entrypoints.ssh_askpass"],
            env=environment,
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "live password"


@pytest.mark.skipif(os.name == "nt", reason="the helper is a POSIX shell script")
def test_the_helper_script_runs_as_ssh_would_run_it(tmp_path):
    import os
    import subprocess
    import sys

    from hydra.services.nodes.ssh_auth import SshPasswordAuth

    with SshPasswordAuth("live password") as auth:
        environment = auth.environment(interpreter=sys.executable)
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [environment["SSH_ASKPASS"]],
            env=environment,
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "live password"


def test_the_helper_script_quotes_its_paths():
    from hydra.services.nodes import ssh_auth

    with ssh_auth.SshPasswordAuth("pw") as auth:
        environment = auth.environment(interpreter="/opt/hydra venv/bin/python")
        script = Path(environment["SSH_ASKPASS"]).read_text(encoding="utf-8")
    assert "export PYTHONPATH=" in script
    assert "exec '/opt/hydra venv/bin/python'" in script
    assert "${PYTHONPATH:+:$PYTHONPATH}" in script
