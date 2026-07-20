import queue

from hydra.plugins.antidpi.agent import TextTail, _offer_event


def test_bounded_event_queue_does_not_block_and_keeps_recent_event():
    events = queue.Queue(maxsize=1)
    first = ("198.51.100.1", {"kind": "first"})
    second = ("198.51.100.2", {"kind": "second"})
    _offer_event(events, first)
    _offer_event(events, second)
    assert events.get_nowait() == second


def test_text_tail_normalizes_new_honeypot_lines(tmp_path):
    log = tmp_path / "honeypot.log"
    tail = TextTail(log, "honeypot")
    assert tail.read() == []
    assert not log.exists()
    with log.open("a", encoding="utf-8") as handle:
        handle.write("[2026-07-20] CONNECT 198.51.100.91:45600\n")
    events = tail.read()
    assert events[0][0] == "198.51.100.91"
    assert events[0][1]["kind"] == "active_decoy_probe"
    assert events[0][1]["source"] == "honeypot-log"
