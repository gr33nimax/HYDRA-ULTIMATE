"""Parser regressions for the closed AntiScan evidence allowlist.

The positive fixtures are real sanitized captures from the deployed host; see
``tests/fixtures/antidpi/MANIFEST.md``.  A parser change that stops matching
them ships a detector that silently does nothing, so these assertions are the
contract, not an illustration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hydra.plugins.antidpi.adapters import (
    decode_log_message,
    parse_protocol_line,
    remote_ip,
)
from hydra.plugins.antidpi.detection import evidence_problem, is_enforcement_evidence
from hydra.plugins.antidpi.normalization import (
    DECOY_PATH_TOKENS,
    normalize_decoy_record,
)

FIXTURES = Path(__file__).parent / "fixtures" / "antidpi"
SNELL = FIXTURES / "snell-cipher-auth-failure.txt"
DECOY = FIXTURES / "decoy-scanner-paths.jsonl"
NEGATIVES = FIXTURES / "negatives.jsonl"


def _snell_lines() -> list[str]:
    return [line for line in SNELL.read_text(encoding="utf-8").splitlines() if line.strip()]


def _decoy_records() -> list[dict]:
    return [json.loads(line) for line in DECOY.read_text(encoding="utf-8").splitlines() if line.strip()]


def _negatives() -> dict[str, dict]:
    return {
        entry["kind"]: entry
        for entry in (json.loads(line) for line in NEGATIVES.read_text(encoding="utf-8").splitlines() if line.strip())
    }


def test_fixtures_exist_and_are_sanitized():
    """A missing or leaked fixture must fail loudly, not silently disable a test."""
    for path in (SNELL, DECOY, NEGATIVES, FIXTURES / "MANIFEST.md"):
        assert path.exists(), f"missing fixture: {path}"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in (SNELL, DECOY, NEGATIVES))
    for address in ("95.139.44.62", "34.102.28.45", "129.159.56.14"):
        assert address not in combined, "real capture address was not sanitized"


@pytest.mark.parametrize("line", _snell_lines())
def test_real_snell_reject_is_still_parsed_but_not_enforceable(line):
    """The parser keeps its diagnostic value; the allowlist no longer accepts it.

    Every captured record-header failure must still normalize identically — the
    capture pipeline depends on it — while none of them may reach the firewall.
    """
    match = parse_protocol_line("sing-box", line)
    assert match is not None, line
    address, event = match
    assert remote_ip(address) == address
    assert event == {
        "kind": "protocol_reject",
        "protocol": "snell",
        "reason": "record_auth_failed",
        "source": "journal",
        "attribution": "direct",
    }
    assert not is_enforcement_evidence(event)
    assert evidence_problem(event) != ""


def test_all_captured_snell_tags_are_recognized():
    """Four different inbound tags appear in production; all must match."""
    assert len({line.split("inbound/snell[")[1].split("]")[0] for line in _snell_lines()}) >= 3
    assert all(parse_protocol_line("sing-box", line) for line in _snell_lines())


def test_peer_mismatch_is_never_attributed():
    """Wrapper and protocol-owned error disagreeing on the peer means no proof."""
    line = (
        "+0000 2026-09-16 13:45:24 ERROR [1 20ms] "
        "inbound/snell[snell-1111aaaa2222-in]: process connection from "
        "203.0.113.44:8235: snell: serve 198.51.100.9:8235: read request: "
        "open record header: cipher: message authentication failed"
    )
    assert parse_protocol_line("sing-box", line) is None


def test_journal_byte_array_messages_are_decoded():
    """sing-box-extended writes []byte through journald; both shapes must parse."""
    payload = _snell_lines()[0].encode("utf-8")
    encoded = json.dumps(list(payload))
    assert decode_log_message(encoded) == _snell_lines()[0]
    assert parse_protocol_line("sing-box", encoded) is not None


def test_unrelated_snell_error_is_not_auth_evidence():
    """Only the record-header authentication failure is proof."""
    record = _negatives()["snell_unrelated_error"]["record"]
    assert parse_protocol_line("sing-box", record["msg"]) is None


def test_successful_snell_session_is_not_evidence():
    record = _negatives()["snell_successful_session"]["record"]
    assert parse_protocol_line("sing-box", record["msg"]) is None


def test_other_inbound_is_never_attributed_to_snell():
    record = _negatives()["other_inbound_tag"]["record"]
    assert parse_protocol_line("sing-box", record["msg"]) is None


@pytest.mark.parametrize(
    "kind",
    ["generic_tls_no_certificate", "generic_tls_eof", "generic_tls_unknown_sni"],
)
def test_generic_tls_noise_never_becomes_evidence(kind):
    """These produced 77265 lines and 39914 alerts on the live host."""
    record = _negatives()[kind]["record"]
    assert parse_protocol_line("caddy-l4", json.dumps(record)) is None
    assert parse_protocol_line("caddy-l4", record["error"]) is None


@pytest.mark.parametrize(
    "kind",
    [
        "generic_tls_no_certificate",
        "generic_tls_eof",
        "generic_tls_unknown_sni",
        "normal_decoy_asset",
        "decoy_query_string_only",
    ],
)
def test_negatives_are_not_decoy_scans(kind):
    record = _negatives()[kind]["record"]
    assert normalize_decoy_record(record) is None


def test_unauthenticated_naive_connect_is_not_evidence():
    """Production shows 404 here, never 407: there is no attributable reject."""
    record = _negatives()["naive_unauthenticated_decoy"]["record"]
    assert normalize_decoy_record(record) is None


@pytest.mark.parametrize("record", _decoy_records())
def test_real_decoy_scans_are_evidence(record):
    match = normalize_decoy_record(record)
    assert match is not None, record.get("request", {}).get("uri")
    address, event = match
    assert address
    assert event["kind"] == "decoy_scan"
    assert event["reason"] == "scanner_path"
    assert event["attribution"] == "direct"
    assert is_enforcement_evidence(event)


def test_decoy_allowlist_covers_the_paths_production_actually_probes():
    """`/.git/` was missing before the contraction and is the second-biggest hit."""
    probed = {record["request"]["uri"].lower() for record in _decoy_records()}
    assert any(uri.startswith("/.env") for uri in probed)
    assert any(uri.startswith("/.git/") for uri in probed)
    for uri in probed:
        assert any(uri.startswith(token) for token in DECOY_PATH_TOKENS), uri


def test_evidence_path_is_bounded_and_printable():
    record = {
        "request": {
            "remote_ip": "203.0.113.5",
            "uri": "/.env" + "A" * 500 + "\x07\x1b[31m",
        },
    }
    match = normalize_decoy_record(record)
    assert match is not None
    path = match[1]["path"]
    assert len(path) <= 120
    assert path.isprintable()
