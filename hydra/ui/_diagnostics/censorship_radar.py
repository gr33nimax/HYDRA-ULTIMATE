"""RIPE Atlas measurement workflow for the TSPU diagnostic."""
from __future__ import annotations

import json

from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
)


_ATLAS_API_KEY = "dbfb4e08-e6fe-4d8c-a180-3a416688e7dc"
_ATLAS_ASNS = (
    (12389, 3),
    (8402, 5),
    (25513, 5),
    (8359, 3),
    (3216, 3),
    (20485, 2),
    (25490, 1),
    (43727, 1),
    (12714, 4),
    (34757, 2),
    (29124, 2),
    (12768, 2),
)


def _measurement_payload(target_ip: str, sni: str) -> dict:
    probes = [
        {
            "requested": requested,
            "type": "asn",
            "value": asn,
            "tags": {"include": ["system-ipv4-works"]},
        }
        for asn, requested in _ATLAS_ASNS
    ]
    return {
        "definitions": [
            {
                "target": target_ip,
                "description": "Reality TLS Handshake",
                "type": "sslcert",
                "port": 443,
                "hostname": sni,
                "af": 4,
            },
        ],
        "probes": probes,
        "is_oneoff": True,
    }


def _create_measurement(target_ip: str, sni: str) -> object:
    response = current_diagnostic_operations().request(
        "https://atlas.ripe.net/api/v2/measurements/",
        method="POST",
        data=json.dumps(_measurement_payload(target_ip, sni)).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Key {_ATLAS_API_KEY}",
        },
        timeout=5.0,
    )
    if response.error_kind:
        raise RuntimeError(response.error_detail or response.error_kind)
    return json.loads(response.text())["measurements"][0]


def _poll_results(measurement_id: object) -> list[dict]:
    url = (
        "https://atlas.ripe.net/api/v2/measurements/"
        f"{measurement_id}/results/"
    )
    results: list[dict] = []
    last_count = 0
    stagnant_attempts = 0
    for _attempt in range(15):
        current_diagnostic_operations().sleep(2.0)
        try:
            response = current_diagnostic_operations().request(
                url,
                timeout=3.0,
            )
            results = json.loads(response.text())
            current_count = len(results)
            if current_count >= 33:
                break
            if current_count > 0 and current_count == last_count:
                stagnant_attempts += 1
            else:
                stagnant_attempts = 0
            last_count = current_count
            if stagnant_attempts >= 3 and current_count >= 10:
                break
        except Exception:
            pass
    return results


def _blocked_probes(results: list[dict]) -> tuple[int, list[object]]:
    successful_markers = ("cert", "method", "alert")
    blocked = [
        probe
        for probe in results
        if not any(marker in probe for marker in successful_markers)
    ]
    return len(blocked), [
        probe["prb_id"] for probe in blocked if probe.get("prb_id")
    ]


def _blocked_asns(probe_ids: list[object]) -> dict[object, int]:
    if not probe_ids:
        return {}
    try:
        ids = ",".join(str(probe_id) for probe_id in probe_ids)
        response = current_diagnostic_operations().request(
            "https://atlas.ripe.net/api/v2/probes/"
            f"?id__in={ids}&fields=id,asn_v4",
            timeout=5.0,
        )
        counts: dict[object, int] = {}
        for probe in json.loads(response.text()).get("results", []):
            asn = probe.get("asn_v4")
            if asn:
                counts[asn] = counts.get(asn, 0) + 1
        return counts
    except Exception:
        return {}


def run_tspu_radar(target_ip: str, sni: str) -> dict:
    """Run a RIPE Atlas TLS measurement and aggregate blocked probes."""
    try:
        measurement_id = _create_measurement(target_ip, sni)
    except Exception as exc:
        return {"status": "error", "message": f"API create error: {exc}"}

    results = _poll_results(measurement_id)
    if not results:
        return {
            "status": "error",
            "message": "No data received from RIPE probes",
        }
    blocked, blocked_ids = _blocked_probes(results)
    return {
        "status": "success",
        "total": len(results),
        "success": len(results) - blocked,
        "blocked": blocked,
        "blocked_asns": _blocked_asns(blocked_ids),
    }


__all__ = ["run_tspu_radar"]
