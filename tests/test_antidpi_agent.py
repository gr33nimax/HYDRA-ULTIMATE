import queue
from unittest.mock import patch

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.agent import (
    TextTail,
    _journal_follow_command,
    _normalize_journal_record,
    _offer_event,
)


def test_bounded_event_queue_does_not_block_and_keeps_recent_event():
    events = queue.Queue(maxsize=1)
    first = ("198.51.100.1", {"kind": "first"})
    second = ("198.51.100.2", {"kind": "second"})
    _offer_event(events, first)
    _offer_event(events, second)
    assert events.get_nowait() == second


def test_text_tail_normalizes_new_protocol_lines(tmp_path):
    log = tmp_path / "sing-box.log"
    log.write_text("handshake failed 198.51.100.90\n", encoding="utf-8")
    tail = TextTail(log, "sing-box")
    assert tail.read() == []
    with log.open("a", encoding="utf-8") as handle:
        handle.write("handshake failed 198.51.100.91\n")
    events = tail.read()
    assert events[0][0] == "198.51.100.91"
    assert events[0][1]["kind"] == "handshake_failure"
    assert events[0][1]["source"] == "sing-box-log"


def test_antidpi_uses_one_filtered_journal_stream_for_services_and_kernel():
    command = _journal_follow_command()

    assert command[:5] == ["journalctl", "-f", "-n", "0", "-o"]
    assert "_SYSTEMD_UNIT=sing-box.service" in command
    assert "+" in command
    assert "_TRANSPORT=kernel" in command


def test_combined_journal_stream_preserves_kernel_event_attribution():
    parsed = ("198.51.100.44", {"kind": "udp_probe"})
    with (
        patch(
            "hydra.plugins.antidpi.agent.parse_kernel_scan_line",
            return_value=parsed,
        ) as parse,
        patch(
            "hydra.plugins.antidpi.agent._attribute_udp_protocol",
            side_effect=lambda event, _reader: event,
        ),
    ):
        event = _normalize_journal_record(
            {"_TRANSPORT": "kernel", "MESSAGE": "kernel probe"},
            lambda: AppState(),
        )

    assert event == parsed
    parse.assert_called_once_with("kernel probe")
