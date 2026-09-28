"""Collector contracts for the AntiScan journal stream.

The collector subscribes to exactly one journal stream and normalizes records
through the strict parser.  Records that carry no proven evidence must come out
as ``None`` so they never reach state, the firewall or Telegram.
"""

from __future__ import annotations

import queue
from pathlib import Path

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.agent import (
    _journal_follow_command,
    _normalize_journal_record,
    _offer_event,
)

FIXTURES = Path(__file__).parent / "fixtures" / "antidpi"
SNELL_IP = "203.0.113.44"


def _snell_line() -> str:
    return next(
        line
        for line in (FIXTURES / "snell-cipher-auth-failure.txt").read_text(encoding="utf-8").splitlines()
        if SNELL_IP in line
    )


def test_bounded_event_queue_does_not_block_and_keeps_recent_event():
    events: queue.Queue = queue.Queue(maxsize=1)
    first = ("198.51.100.1", {"kind": "first"})
    second = ("198.51.100.2", {"kind": "second"})
    _offer_event(events, first)
    _offer_event(events, second)
    assert events.get_nowait() == second


def test_journal_stream_subscribes_only_to_the_proven_protocol_unit():
    command = _journal_follow_command()

    assert command[:5] == ["journalctl", "-f", "-n", "0", "-o"]
    assert "_SYSTEMD_UNIT=sing-box.service" in command
    # The kernel transport and the other unit filters carried the removed
    # scan, UDP and per-protocol telemetry.
    assert "_TRANSPORT=kernel" not in command
    assert "+" not in command
    for unit in ("amneziawg", "hysteria2", "mieru", "telemt", "wdtt", "caddy-l4"):
        assert f"_SYSTEMD_UNIT={unit}.service" not in command


def test_journal_record_with_a_proven_reject_normalizes():
    record = {
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": _snell_line(),
    }
    event = _normalize_journal_record(record, AppState)

    assert event is not None
    address, details = event
    assert address == SNELL_IP
    assert details["kind"] == "protocol_reject"
    assert details["protocol"] == "snell"
    assert details["source"] == "journal"
    assert details["attribution"] == "direct"


def test_journal_record_without_proven_evidence_is_discarded():
    """Generic failures, other inbounds and boilerplate must all be silent."""
    for message in (
        "handshake failed from 198.51.100.90:443",
        "no certificate available for 'no-such.invalid'",
        "inbound/vless[vless-xhttp-in]: process connection from "
        "198.51.100.9:1234: unknown UUID: "
        "00000000-0000-0000-0000-000000000000",
        "inbound/snell[snell-1111aaaa2222-in]: [user] inbound connection to example.com:443",
        "HYDRA_SCAN_TCP SRC=198.51.100.9 DPT=1001",
    ):
        assert (
            _normalize_journal_record(
                {"_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": message},
                AppState,
            )
            is None
        ), message


def test_collector_has_no_text_tail_or_kernel_normalizer():
    """Removed seams must not linger: a text tail could never enforce.

    ``TextTail`` stamped its events with a ``<service>-log`` source, which is
    outside the evidence allowlist, so wiring it up would silently disable
    enforcement instead of failing loudly.
    """
    from hydra.plugins.antidpi import agent, adapters

    assert not hasattr(agent, "TextTail")
    assert not hasattr(agent, "_attribute_udp_protocol")
    assert not hasattr(agent, "_resolve_relay_source")
    assert not hasattr(adapters, "parse_kernel_scan_line")
