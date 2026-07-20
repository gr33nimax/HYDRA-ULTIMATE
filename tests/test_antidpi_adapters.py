from hydra.plugins.antidpi.adapters import parse_protocol_line


def test_awg_rejection_is_normalized():
    result = parse_protocol_line("amneziawg.service", "Invalid MAC of handshake from 203.0.113.9:48120")
    assert result == ("203.0.113.9", {"protocol": "amneziawg", "kind": "handshake_failure", "handshake_ok": False, "source": "journal"})


def test_non_evidence_is_ignored():
    assert parse_protocol_line("sing-box.service", "accepted connection from 203.0.113.9") is None
