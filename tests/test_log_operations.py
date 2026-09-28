from __future__ import annotations

import ast
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock

from hydra.services.log_infrastructure import HostLogOperations


ROOT = Path(__file__).parents[1]


def _operations(
    *,
    run_command: Mock | None = None,
    unit_active: Mock | None = None,
    unit_known: Mock | None = None,
) -> HostLogOperations:
    return HostLogOperations(
        run_command=run_command or Mock(),
        popen_command=Mock(),
        unit_active=unit_active or Mock(return_value=False),
        unit_known=unit_known or Mock(return_value=False),
    )


def test_file_log_read_is_bounded_to_requested_tail(tmp_path: Path) -> None:
    path = tmp_path / "service.log"
    path.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")

    result = _operations().read("file", str(path), 2)

    assert result.lines == ("three", "four")
    assert result.message == ""


def test_missing_file_has_explicit_unavailable_projection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing.log"
    operations = _operations()

    result = operations.read("file", str(path), 10)
    info = operations.source_info("file", str(path))

    assert result.lines == ()
    assert "не создан" in result.message
    assert info.available is False


def test_journal_read_uses_injected_command_runner() -> None:
    run_command = Mock(
        return_value=CompletedProcess(
            args=[],
            returncode=0,
            stdout="2026 first\n2026 second\n",
            stderr="",
        ),
    )
    operations = _operations(run_command=run_command)

    result = operations.read("journal", "sing-box", 25)

    assert result.lines == ("2026 first", "2026 second")
    command = run_command.call_args.args[0]
    assert command[:3] == ["journalctl", "-u", "sing-box"]
    assert "25" in command


def test_journal_projection_redacts_upstream_vk_join_link() -> None:
    run_command = Mock(
        return_value=CompletedProcess(
            args=[],
            returncode=0,
            stdout="INFO https://vk.com/call/join/shared-room\n",
            stderr="",
        ),
    )
    result = _operations(run_command=run_command).read("journal", "sing-box", 10)
    assert result.lines == ("INFO https://vk.com/call/join/<redacted>",)


def test_journal_failure_message_redacts_upstream_vk_join_link() -> None:
    run_command = Mock(
        return_value=CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="failed https://vk.com/call/join/shared-room\n",
        ),
    )
    result = _operations(run_command=run_command).read("journal", "sing-box", 10)
    assert result.message == "failed https://vk.com/call/join/<redacted>"


def test_journal_info_uses_injected_unit_queries() -> None:
    active = Mock(return_value=True)
    known = Mock(return_value=True)

    info = _operations(
        unit_active=active,
        unit_known=known,
    ).source_info("journal", "sing-box")

    assert info.available is True
    assert info.active is True
    assert info.loaded is True
    active.assert_called_once_with("sing-box")
    known.assert_called_once_with("sing-box")


def test_log_viewer_is_presentation_only() -> None:
    path = ROOT / "hydra" / "ui" / "log_viewer.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden_imports = {
        "hydra.core.host",
        "pathlib",
        "select",
        "subprocess",
    }
    violations: list[str] = []
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        for module in modules:
            if module in forbidden_imports:
                violations.append(f"{node.lineno}: {module}")
        if isinstance(node, ast.Name) and node.id == "HOST":
            violations.append(f"{node.lineno}: HOST")

    assert violations == []
