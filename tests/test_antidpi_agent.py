import queue

from hydra.plugins.antidpi.agent import TextTail, _offer_event


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
