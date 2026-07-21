from hydra.plugins.antidpi.adapters import decode_log_message, parse_kernel_scan_line, parse_protocol_line


def test_awg_rejection_is_normalized():
    result = parse_protocol_line("amneziawg.service", "Invalid MAC of handshake from 203.0.113.9:48120")
    assert result == ("203.0.113.9", {"protocol": "amneziawg", "kind": "handshake_failure", "handshake_ok": False, "source": "journal"})


def test_non_evidence_is_ignored():
    assert parse_protocol_line("sing-box.service", "accepted connection from 203.0.113.9") is None


def test_honeypot_events_are_not_antidpi_evidence():
    assert parse_protocol_line(
        "honeypot", "BAN 198.51.100.91 backend=iptables result=OK",
    ) is None
    assert parse_protocol_line(
        "honeypot", "CONNECT 198.51.100.91:45600",
    ) is None


def test_kernel_tcp_scan_is_normalized():
    line = "HYDRA_SCAN_TCP IN=eth0 SRC=198.51.100.77 DST=192.0.2.1 SPT=44222 DPT=22"
    assert parse_kernel_scan_line(line) == (
        "198.51.100.77",
        {
            "protocol": "tcp",
            "kind": "port_scan",
            "source": "kernel-firewall",
            "connections_10s": 12,
            "destination_port": 22,
        },
    )


def test_unrelated_kernel_message_is_ignored():
    assert parse_kernel_scan_line("TCP: harmless kernel diagnostic") is None


def test_protocol_error_with_ip_before_message_is_normalized():
    result = parse_protocol_line(
        "sing-box.service",
        "peer 198.51.100.88:45500 handshake failed: protocol error",
    )
    assert result is not None
    assert result[0] == "198.51.100.88"
    assert result[1]["kind"] == "handshake_failure"


def test_singbox_journal_byte_array_is_decoded_and_anytls_auth_is_normalized():
    line = (
        "+0000 ERROR inbound/anytls[anytls-in]: process connection from "
        "127.0.0.1:14902: unknown user password: fallback disabled"
    )
    encoded = list(line.encode())
    assert decode_log_message(encoded) == line
    assert parse_protocol_line("sing-box.service", encoded) == (
        "127.0.0.1",
        {"protocol": "anytls", "kind": "auth_failure", "source": "journal"},
    )


def test_anytls_eof_and_wdtt_native_errors_are_normalized():
    anytls = parse_protocol_line(
        "sing-box.service",
        "inbound/anytls[anytls-in]: process connection from 198.51.100.7:1234: EOF: fallback disabled",
    )
    assert anytls == (
        "198.51.100.7",
        {"protocol": "anytls", "kind": "invalid_first_packet", "source": "journal"},
    )
    wdtt = parse_protocol_line(
        "wdtt.service",
        "[DTLS] [ERR] Handshake failed from 198.51.100.8:24420: handshake error: dtls fatal",
    )
    assert wdtt == (
        "198.51.100.8",
        {"protocol": "wdtt", "kind": "handshake_failure", "handshake_ok": False, "source": "journal"},
    )
