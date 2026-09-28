"""Black-box contract tests for the dependency-free decision journal CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


NODE = shutil.which("node")
SCRIPT = Path(__file__).parents[1] / "scripts" / "decisions.mjs"


@pytest.fixture
def cli_root(tmp_path: Path) -> Path:
    if NODE is None:
        pytest.skip("node is required for decisions-cli tests")
    root = tmp_path / "project"
    destination = root / "scripts" / "decisions.mjs"
    destination.parent.mkdir(parents=True)
    shutil.copy2(SCRIPT, destination)
    return root


def run_cli(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    if NODE is None:
        pytest.skip("node is required for decisions-cli tests")
    workdir = root / "unrelated-cwd"
    workdir.mkdir(exist_ok=True)
    return subprocess.run(
        [NODE, root / "scripts" / "decisions.mjs", *args],
        cwd=workdir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def write_decision(root: Path, number: str, status: str | None = "accepted") -> Path:
    decisions = root / ".kiro" / "decisions"
    decisions.mkdir(parents=True, exist_ok=True)
    status_block = f"**Status:** {status}\n\n" if status else ""
    target = decisions / f"{number}-existing-decision.md"
    target.write_text(
        f"# {number} — Existing decision\n\n{status_block}"
        "## Context\n\nWhy.\n\n## Decision\n\nWhat.\n\n"
        "## Consequences\n\nResult.\n\n## Links\n\n- `docs/ARCHITECTURE.md`\n",
        encoding="utf-8",
    )
    return target


def add_args() -> tuple[str, ...]:
    return (
        "add",
        "--title",
        "Hydra owned layout",
        "--context",
        "Need isolated files",
        "--decision",
        "Use Hydra paths",
        "--consequences",
        "mtbuddy remains isolated",
        "--link",
        ".kiro/specs/mtproto-zig-transport/requirements.md",
    )


def test_scan_reports_legacy_status_without_writing(cli_root: Path) -> None:
    decision = write_decision(cli_root, "0001", status=None)
    before = decision.read_bytes()

    result = run_cli(cli_root, "scan")

    assert result.returncode == 1
    assert "[unknown]" in result.stdout
    assert decision.read_bytes() == before
    assert not (cli_root / ".kiro" / "decisions" / "README.md").exists()


def test_add_review_and_approve_use_root_relative_journal(cli_root: Path) -> None:
    write_decision(cli_root, "0003")
    readme = cli_root / ".kiro" / "decisions" / "README.md"
    readme.write_text(
        "# Decision Log\n\nKeep this text.\n\n| NNNN | Заголовок | Статус |\n"
        "| --- | --- | --- |\n| 0003 | Existing decision | accepted |\n",
        encoding="utf-8",
    )

    added = run_cli(cli_root, *add_args())
    target = cli_root / ".kiro" / "decisions" / "0004-hydra-owned-layout.md"

    assert added.returncode == 0, added.stderr
    assert target.exists()
    assert "**Status:** proposed" in target.read_text(encoding="utf-8")
    assert "Keep this text." in readme.read_text(encoding="utf-8")
    assert "| 0004 | Hydra owned layout | proposed |" in readme.read_text(encoding="utf-8")

    reviewed = run_cli(cli_root, "review", "0004")
    assert reviewed.returncode == 0, reviewed.stderr
    assert "Score: 6/6" in reviewed.stdout

    approved = run_cli(cli_root, "approve", "0004")
    assert approved.returncode == 0, approved.stderr
    assert "**Status:** accepted" in target.read_text(encoding="utf-8")
    assert "| 0004 | Hydra owned layout | accepted |" in readme.read_text(encoding="utf-8")


def test_invalid_input_and_unknown_approval_do_not_mutate_journal(cli_root: Path) -> None:
    legacy = write_decision(cli_root, "0001", status=None)
    before = legacy.read_bytes()

    invalid = run_cli(cli_root, *add_args()[:-1], "../escape.md")
    refused = run_cli(cli_root, "approve", "0001")

    assert invalid.returncode == 1
    assert "safe repository-relative" in invalid.stderr
    assert refused.returncode == 1
    assert "must be proposed" in refused.stderr
    assert legacy.read_bytes() == before
    assert not (cli_root / ".kiro" / "decisions" / "README.md").exists()


def test_failed_second_rename_rolls_back_document_and_index(cli_root: Path) -> None:
    decisions = cli_root / ".kiro" / "decisions"
    decisions.mkdir(parents=True)
    readme = decisions / "README.md"
    readme.write_text("# Decision Log\n", encoding="utf-8")
    before = readme.read_bytes()
    environment = os.environ | {"NODE_ENV": "test", "DECISIONS_TEST_FAIL_RENAME_AT": "2"}

    result = run_cli(cli_root, *add_args(), env=environment)

    assert result.returncode == 1
    assert "injected rename failure" in result.stderr
    assert not (decisions / "0001-hydra-owned-layout.md").exists()
    assert readme.read_bytes() == before
    assert not (decisions / ".decisions.lock").exists()
    assert not list(decisions.glob("*.tmp-*"))
