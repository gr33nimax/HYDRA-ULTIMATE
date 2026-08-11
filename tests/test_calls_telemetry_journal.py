from __future__ import annotations

import json
import subprocess

from hydra.services.calls_telemetry_journal import collect_calls_journal_events


class _Host:
    def __init__(self, lines: list[str], returncode: int = 0) -> None:
        self.lines = lines
        self.returncode = returncode
        self.commands: list[list[str]] = []

    def run(self, command, **kwargs):
        self.commands.append(command)
        return subprocess.CompletedProcess(
            command,
            self.returncode,
            stdout="\n".join(self.lines),
            stderr="",
        )


def _entry(message: str, cursor: str, timestamp: int) -> str:
    return json.dumps({
        "MESSAGE": message,
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": str(timestamp * 1_000_000),
    })


def test_journal_collector_keeps_only_categories_and_cursor() -> None:
    host = _Host([
        _entry(
            "call multi_user: all VK TURN endpoints failed: secret.example:3478",
            "cursor-1",
            101,
        ),
        _entry("unrelated destination alpha.example", "cursor-2", 102),
        "-- cursor: cursor-2",
    ])

    events, cursor, failed = collect_calls_journal_events(
        host,
        cursor="",
        started_at=100,
    )

    assert failed is False
    assert cursor == "cursor-2"
    assert events == [{
        "kind": "event",
        "timestamp": 101.0,
        "source": "sing_box_journal",
        "code": "turn_all_endpoints_failed",
    }]
    assert "--since=@100" in host.commands[0]
    assert "secret.example" not in json.dumps(events)


def test_journal_collector_resumes_after_cursor_and_fails_closed() -> None:
    host = _Host([], returncode=1)

    events, cursor, failed = collect_calls_journal_events(
        host,
        cursor="opaque-cursor",
        started_at=100,
    )

    assert events == []
    assert cursor == "opaque-cursor"
    assert failed is True
    assert "--after-cursor=opaque-cursor" in host.commands[0]
