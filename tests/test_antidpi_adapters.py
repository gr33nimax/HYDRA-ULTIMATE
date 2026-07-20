from hydra.plugins.antidpi.adapters import parse_kernel_scan_line, parse_protocol_line


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
