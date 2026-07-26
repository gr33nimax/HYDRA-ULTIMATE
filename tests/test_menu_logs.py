from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.services.logs import LogReadResult, LogSourceInfo
from hydra.ui.menus import (
    _log_source_status,
    _read_log_source,
    _sync_agent_log_snapshot,
)


def _application(
    *,
    result: LogReadResult = LogReadResult(),
    source: LogSourceInfo = LogSourceInfo(available=False),
):
    logs = MagicMock()
    logs.read.return_value = result
    logs.source_info.return_value = source
    return SimpleNamespace(logs=logs), logs


def test_read_log_source_uses_bounded_log_port(tmp_path):
    path = str(tmp_path / "service.log")
    app, logs = _application(
        result=LogReadResult(("three", "four"), ""),
    )

    lines, message = _read_log_source("file", path, 2, app)

    assert lines == ["three", "four"]
    assert message == ""
    logs.read.assert_called_once_with("file", path, 2)


def test_read_log_source_reports_normalized_missing_file(tmp_path):
    path = str(tmp_path / "missing.log")
    app, logs = _application(
        result=LogReadResult((), "Файл ещё не создан."),
    )

    lines, message = _read_log_source("file", path, 10, app)

    assert lines == []
    assert "не создан" in message
    logs.read.assert_called_once_with("file", path, 10)


def test_read_log_source_requests_journal_without_spawning_from_ui():
    app, logs = _application(
        result=LogReadResult(
            ("2026-01-01 first", "2026-01-01 second"),
            "",
        ),
    )

    lines, message = _read_log_source("journal", "sing-box", 25, app)

    assert lines == ["2026-01-01 first", "2026-01-01 second"]
    assert message == ""
    logs.read.assert_called_once_with("journal", "sing-box", 25)


def test_journal_status_distinguishes_active_and_missing_units():
    app, _logs = _application(
        source=LogSourceInfo(
            available=True,
            active=True,
            loaded=True,
        ),
    )
    with patch("hydra.ui.menus._unit_active", return_value=True):
        assert _log_source_status("journal", "sing-box", app) == "активно"

    with patch("hydra.ui.menus._unit_active", return_value=False), \
         patch("hydra.ui.menus._unit_known", return_value=False):
        assert _log_source_status("journal", "missing", app) == "не установлено"


def test_sync_agent_log_snapshot_reports_latest_line_and_freshness(tmp_path):
    log = tmp_path / "sync-agent.log"
    modified = 1_784_900_000.0
    app, logs = _application(
        result=LogReadResult(("old", "", "latest"), ""),
        source=LogSourceInfo(available=True, modified_at=modified),
    )

    line, freshness, stale = _sync_agent_log_snapshot(
        log,
        app,
        modified + 301,
    )

    assert line == "latest"
    assert freshness == "5 мин назад"
    assert stale is False
    logs.read.assert_called_once_with("file", str(log), 5)


def test_sync_agent_log_snapshot_marks_missed_intervals_as_stale(tmp_path):
    log = tmp_path / "sync-agent.log"
    modified = 1_784_900_000.0
    app, _logs = _application(
        result=LogReadResult(("last run",), ""),
        source=LogSourceInfo(available=True, modified_at=modified),
    )

    _, freshness, stale = _sync_agent_log_snapshot(
        log,
        app,
        modified + 601,
    )

    assert freshness == "10 мин назад"
    assert stale is True
