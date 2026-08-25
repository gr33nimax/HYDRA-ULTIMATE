from __future__ import annotations

import os
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.calls_telemetry import CallsTelemetryService
from hydra.services.calls_telemetry_correlations import throughput_correlations
from hydra.services.calls_telemetry_infrastructure import CallsTelemetryInfrastructure
from hydra.services.calls_telemetry_storage import CallsTelemetryStore
from hydra.services.calls_telemetry_storage_readers import _sample_analysis_records
from hydra.services.system_monitoring import SystemMetrics


def _state() -> AppState:
    state = AppState(
        users=[
            User(email="alpha@example.com", uuid="a"),
            User(email="bravo@example.com", uuid="b"),
            User(email="charlie@example.com", uuid="c"),
        ],
        protocols={
            "calls": PluginState(
                installed=True,
                enabled=True,
                config={
                    "mode": "vk_parasite",
                    "room_count": 4,
                    "workers": 4,
                    "listen_port": 56002,
                },
            ),
        },
    )
    state.network.clash_api_enabled = True
    return state


def test_service_validates_experiment_and_passes_only_safe_metadata() -> None:
    runtime = MagicMock()
    runtime.start.return_value = {"ok": True, "session_id": "session"}
    service = CallsTelemetryService(runtime)
    state = _state()

    result = service.start(
        state,
        ["ALPHA@example.com", "bravo@example.com", "charlie@example.com"],
    )

    assert result["ok"] is True
    runtime.start.assert_called_once()
    args, kwargs = runtime.start.call_args
    assert args[0] == [
        "alpha@example.com",
        "bravo@example.com",
        "charlie@example.com",
    ]
    assert "duration_seconds" not in kwargs
    assert kwargs["sample_interval_seconds"] == 2
    assert kwargs["max_data_bytes"] == 2048 * 1024 * 1024
    assert kwargs["metadata"]["calls"] == {
        "mode": "vk_parasite",
        "transport": "four_lane_kcp_v9",
            "lane_count": 4,
        "room_count": 4,
            "workers": 4,
        "listen_port": 56002,
        "max_sessions": 128,
        "max_sessions_per_user": 1,
            "max_workers_per_session": 4,
        "max_pending_handshakes": 256,
        "handshake_timeout": "10s",
        "session_idle_timeout": "5m",
        "udp_receive_buffer_bytes": 4 * 1024 * 1024,
        "udp_send_buffer_bytes": 4 * 1024 * 1024,
        "ingress_workers": 0,
        "ingress_queue_packets": 4096,
        "peer_read_queue_packets": 512,
    }
    assert "tester" not in kwargs["metadata"]


@pytest.mark.parametrize(
    ("mutate", "testers", "message"),
    [
        (lambda state: setattr(state.protocols["calls"], "enabled", False), ["alpha@example.com"], "must be enabled"),
        (lambda state: setattr(state.network, "clash_api_enabled", False), ["alpha@example.com"], "Clash API"),
        (lambda state: None, ["missing@example.com"], "unknown tester"),
        (lambda state: None, ["alpha@example.com", "ALPHA@example.com"], "unique"),
    ],
)
def test_service_rejects_an_unusable_experiment(mutate, testers, message) -> None:
    state = _state()
    mutate(state)
    service = CallsTelemetryService(MagicMock())

    with pytest.raises(ValueError, match=message):
        service.start(state, testers)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"sample_interval_seconds": 1}, "between 2 and 300 seconds"),
        ({"sample_interval_seconds": 301}, "between 2 and 300 seconds"),
        ({"max_data_mib": 15}, "between 16 and 65536 MiB"),
        ({"max_data_mib": 65537}, "between 16 and 65536 MiB"),
    ],
)
def test_service_bounds_storage_and_sample_frequency(options, message) -> None:
    service = CallsTelemetryService(MagicMock())

    with pytest.raises(ValueError, match=message):
        service.start(_state(), ["alpha@example.com"], **options)


@dataclass
class _Clock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value


class _Monitoring:
    def __init__(self) -> None:
        self.tick = 0

    def snapshot(self) -> SystemMetrics:
        return SystemMetrics(
            cpu_percent=25.0,
            memory_used=500,
            memory_total=1_000,
            memory_percent=50.0,
            disk_used=0,
            disk_total=0,
            disk_percent=0.0,
            network_rx=10_000,
            network_tx=20_000,
        )

    def cpu_counters(self, stat_path=None) -> tuple[float, float]:
        self.tick += 1
        return 100.0 + self.tick * 10, 200.0 + self.tick * 40

    def load_averages(self) -> tuple[float, float]:
        return 0.5, 0.25


def _runtime(tmp_path: Path, clock: _Clock) -> CallsTelemetryInfrastructure:
    proc_root = tmp_path / "proc"
    (proc_root / "net").mkdir(parents=True)
    _write_udp(proc_root, receive_errors=0, listener_drops=0)
    return CallsTelemetryInfrastructure(
        HostBackend(),
        _Monitoring(),
        state_dir=tmp_path / "state",
        data_dir=tmp_path / "data",
        proc_root=proc_root,
        sys_root=tmp_path / "sys",
        native_path=tmp_path / "native.jsonl",
        clock=clock,
        token_hex=lambda size: "a" * (size * 2),
        clock_ticks_per_second=100,
        page_size=4096,
    )


def _write_udp(proc_root: Path, *, receive_errors: int, listener_drops: int) -> None:
    (proc_root / "net" / "snmp").write_text(
        "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n"
        f"Udp: 100 0 {receive_errors} 200 {receive_errors} 0\n",
        encoding="utf-8",
    )
    (proc_root / "net" / "udp").write_text(
        "  sl  local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode drops\n"
        f"  1: 00000000:DAC2 00000000:0000 07 00000000:00000010 00:00000000 00000000 0 0 1 {listener_drops}\n",
        encoding="utf-8",
    )
    (proc_root / "net" / "udp6").write_text("header\n", encoding="utf-8")


def test_runtime_collects_anonymized_directional_metrics_and_report(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    state = _state()
    start = service.start(
        state,
        ["alpha@example.com", "bravo@example.com", "charlie@example.com"],
        sample_interval_seconds=10,
    )
    session_id = str(start["session_id"])
    state.install["traffic_connection_counters"] = {
        "raw-connection-id": {
            "protocol": "calls",
            "user": "alpha@example.com",
            "upload": 100,
            "download": 200,
            "missed_polls": 0,
        },
    }

    assert runtime.record(state) is False
    state.install["traffic_connection_counters"]["raw-connection-id"].update(
        upload=200,
        download=400,
    )
    clock.value += 10
    assert runtime.record(state) is True

    state.install["traffic_connection_counters"]["raw-connection-id"].update(
        upload=400,
        download=800,
    )
    _write_udp(runtime.proc_root, receive_errors=2, listener_drops=3)
    clock.value += 10
    assert runtime.record(state) is True
    assert runtime.record_event("clash_api_unavailable") is True

    report = service.report(session_id)

    assert report["window"]["coverage_ratio"] == 1.0
    assert report["calls"]["total_bytes"] == 900
    assert report["testers"][0]["tester_id"] == "tester-1"
    assert report["testers"][0]["total_bytes"] == 900
    assert report["resources"]["udp"]["receive_buffer_errors"] == 2
    assert report["resources"]["udp"]["listener_drops"] == 3
    assert {finding["code"] for finding in report["findings"]} >= {
        "udp_receive_drops",
        "telemetry_source_unavailable",
    }

    control = (runtime.state_dir / f"{session_id}.json").read_text(encoding="utf-8")
    samples = (runtime.data_dir / f"{session_id}.jsonl").read_text(encoding="utf-8")
    combined = control + samples
    assert "alpha@example.com" not in combined
    assert "raw-connection-id" not in combined
    assert "destination" not in samples
    assert "tester-1" in samples
    if os.name != "nt":
        assert (runtime.state_dir / f"{session_id}.json").stat().st_mode & 0o777 == 0o600
        assert (runtime.data_dir / f"{session_id}.jsonl").stat().st_mode & 0o777 == 0o600

    clock.value += 1
    stopped = service.stop()
    assert stopped["stopped"] is True
    assert stopped["active"] is False


def test_runtime_ignores_native_history_before_operator_start(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    payload = {
        "schema": 1,
        "timestamp": clock.value,
        "scope": "server",
        "kind": "snapshot",
        "session_id": "server-0123456789abcdef",
        "metrics": {"worker_active": 1},
    }
    runtime.native_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    service = CallsTelemetryService(runtime)
    service.start(_state(), ["alpha@example.com"])

    runtime.record(_state())
    assert runtime.store.active_session(required=True)["native_record_count"] == 0

    clock.value += 1
    payload["timestamp"] = clock.value
    with runtime.native_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
    runtime.record(_state())

    assert runtime.store.active_session(required=True)["native_record_count"] == 1


class _FailActivePointerHost(HostBackend):
    def atomic_write(self, path: Path, content, *, mode: int = 0o644) -> None:
        if path.name == "active.json":
            raise OSError("injected pointer failure")
        super().atomic_write(path, content, mode=mode)


def test_failed_start_never_publishes_a_partial_active_session(tmp_path) -> None:
    clock = _Clock()
    runtime = CallsTelemetryInfrastructure(
        _FailActivePointerHost(),
        _Monitoring(),
        state_dir=tmp_path / "state",
        data_dir=tmp_path / "data",
        proc_root=tmp_path / "proc",
        clock=clock,
        token_hex=lambda size: "b" * (size * 2),
    )

    with pytest.raises(OSError, match="injected"):
        CallsTelemetryService(runtime).start(_state(), ["alpha@example.com"])

    assert runtime.active_file.exists() is False
    assert runtime.status() == {
        "ok": True,
        "active": False,
        "session_id": "",
        "samples": 0,
    }


def test_report_rejects_session_path_traversal(tmp_path) -> None:
    runtime = _runtime(tmp_path, _Clock())

    with pytest.raises(ValueError, match="invalid Calls telemetry session id"):
        runtime.report("../../state")


def test_session_has_no_time_limit_and_stops_only_on_operator_request(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    service.start(_state(), ["alpha@example.com"])

    clock.value += 40 * 24 * 3600

    assert service.status()["active"] is True
    assert service.status()["elapsed_seconds"] == 40 * 24 * 3600
    assert service.stop()["stop_reason"] == "operator"
    assert service.status()["active"] is False


def test_storage_limit_stops_without_rotating_existing_timeline(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    started = service.start(_state(), ["alpha@example.com"])
    session = runtime.store.active_session(required=True)
    before = runtime._samples_path(str(started["session_id"])).read_bytes()
    session["max_data_bytes"] = len(before) + 8
    runtime.store.write_session(session)

    clock.value += 2

    assert runtime.record(_state()) is False
    assert service.status()["active"] is False
    assert service.status()["stop_reason"] == "storage_limit"
    assert runtime._samples_path(str(started["session_id"])).read_bytes() == before


def test_timeline_segments_compress_without_losing_tail_report_or_export(tmp_path) -> None:
    clock = _Clock()
    store = CallsTelemetryStore(
        HostBackend(),
        tmp_path / "state",
        tmp_path / "data",
        clock,
        segment_bytes=1024,
    )
    session = {
        "schema": 2,
        "session_id": "20260811T120000Z-deadbeef",
        "started_at": clock.value,
        "stopped_at": 0.0,
        "max_data_bytes": 1024 * 1024,
        "data_bytes": 0,
        "raw_data_bytes": 0,
        "compressed_bytes": 0,
        "timeline_segments": 0,
        "sequence": 0,
        "sample_count": 0,
    }
    store.publish(session)
    for index in range(40):
        assert store.append_record(
            session,
            {
                "kind": "sample",
                "timestamp": clock.value + index,
                "payload": "same-technical-payload-" * 8,
            },
            counter="sample_count",
        )

    assert store.segment_paths(str(session["session_id"]))
    assert int(session["data_bytes"]) < int(session["raw_data_bytes"])
    assert len(store.records(str(session["session_id"]))) == 40
    assert [record["sequence"] for record in store.tail(str(session["session_id"]), limit=3)] == [38, 39, 40]
    target = store.export(session, {"ok": True}, str(tmp_path / "segmented.tar.gz"))
    with tarfile.open(target, "r:gz") as archive:
        timeline = archive.extractfile("timeline.jsonl").read().decode("utf-8")
    assert len(timeline.splitlines()) == 40


def test_live_analysis_uses_one_immutable_timeline_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    clock = _Clock()
    store = CallsTelemetryStore(
        HostBackend(),
        tmp_path / "state",
        tmp_path / "data",
        clock,
    )
    session = {
        "schema": 2,
        "session_id": "20260811T120000Z-feedface",
        "started_at": clock.value,
        "stopped_at": 0.0,
        "max_data_bytes": 1024 * 1024,
        "sequence": 0,
    }
    store.publish(session)
    worker = {
        "kind": "native",
        "native_kind": "snapshot",
        "native_entity": "server_worker",
        "tester_id": "tester-2",
        "native_session_id": "native-session",
        "worker_id": 0,
        "timestamp": clock.value,
        "metrics": {"telemetry_sequence": 1},
    }
    assert store.append_record(session, worker)

    original = store._iter_sources
    passes = 0

    def grow_after_first_pass(sources):
        nonlocal passes
        passes += 1
        yield from original(sources)
        if passes == 1:
            assert store.append_record(session, worker | {
                "native_kind": "event",
                "event": "worker_reconnect",
                "timestamp": clock.value + 1,
            })

    monkeypatch.setattr(store, "_iter_sources", grow_after_first_pass)
    records, analysis = store.analysis_records(str(session["session_id"]))

    assert passes == 2
    assert [record["native_kind"] for record in records] == ["snapshot"]
    assert analysis["timeline_records"] == 1
    assert len(store.records(str(session["session_id"]))) == 2


def test_analysis_sampling_keeps_both_sides_of_native_counter_resets() -> None:
    def records():
        for sequence in range(100):
            counter = sequence if sequence < 50 else sequence - 50
            yield {
                "kind": "native",
                "native_kind": "snapshot",
                "native_scope": "client",
                "native_entity": "client_session",
                "tester_id": "tester-1",
                "native_session_id": "client-session",
                "timestamp": float(sequence),
                "metrics": {
                    "telemetry_sequence": sequence + 1,
                    "outer_bytes_out_total": counter,
                },
            }

    retained, analysis = _sample_analysis_records(
        lambda: iter(records()),
        native_budget=32,
    )

    retained_timestamps = {record["timestamp"] for record in retained}
    assert {49.0, 50.0} <= retained_timestamps
    assert analysis["timeline_records"] == 100
    assert analysis["analyzed_records"] < analysis["timeline_records"]


def test_mark_tail_follow_and_live_export_share_one_timeline(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    state = _state()
    started = service.start(state, ["alpha@example.com"], sample_interval_seconds=2)
    session_id = str(started["session_id"])

    assert service.mark("wifi_speedtest")["ok"] is True
    runtime.record(state)
    clock.value += 2
    assert runtime.record(state) is True
    export = service.export(session_id, str(tmp_path / "bundle.tar.gz"))

    assert export["active"] is True
    assert service.status()["active"] is True
    tail = service.tail(session_id, limit=10)
    assert {record["kind"] for record in tail["records"]} >= {"event", "mark", "sample"}

    service.stop()
    followed = list(service.follow(session_id, limit=10))
    assert followed[-1]["code"] == "session_stopped"
    with tarfile.open(export["output"], "r:gz") as archive:
        assert set(archive.getnames()) == {
            "SCHEMA.txt",
            "manifest.json",
            "report.json",
            "timeline.jsonl",
        }
        manifest = json.load(archive.extractfile("manifest.json"))
        timeline = archive.extractfile("timeline.jsonl").read().decode()
    assert "salt" not in manifest
    assert "tester_hashes" not in manifest
    assert "alpha@example.com" not in timeline


def test_native_core_records_are_pseudonymized_and_reported(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    state = _state()
    started = service.start(state, ["alpha@example.com"])
    native_session = "raw-native-session-secret"
    runtime.native_path.write_text(
        json.dumps({
            "schema": 1,
            "timestamp": clock.value,
            "scope": "client",
            "kind": "snapshot",
            "user": "alpha@example.com",
            "session_id": native_session,
            "worker_id": 0,
            "metrics": {
                "vk_auth_success_total": 1,
                "vk_auth_failure_total": 0,
                "vk_auth_latency_ms": 120.5,
                "worker_active": 4,
                "kcp_rtt_ms": 85.0,
            },
        }) + "\n",
        encoding="utf-8",
    )
    clock.value += 2

    assert runtime.record(state) is True
    report = service.report(str(started["session_id"]))
    timeline = runtime._samples_path(str(started["session_id"])).read_text(
        encoding="utf-8",
    )

    assert report["native"]["available"] is True
    assert report["native"]["diagnostic_level"] == "partial"
    assert report["native"]["clients"]["tester-1"]["records"] == 1
    assert "alpha@example.com" not in timeline
    assert native_session not in timeline
    assert "native-" in timeline


def test_connection_lifecycle_detects_short_and_zero_byte_flows(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    state = _state()
    started = service.start(state, ["alpha@example.com"], sample_interval_seconds=2)
    runtime.record(state)
    state.install["traffic_connection_counters"] = {
        "short": {
            "protocol": "calls",
            "user": "alpha@example.com",
            "upload": 0,
            "download": 0,
            "missed_polls": 0,
        },
    }
    clock.value += 2
    runtime.record(state)
    state.install["traffic_connection_counters"]["short"]["missed_polls"] = 1
    clock.value += 2
    runtime.record(state)

    report = service.report(str(started["session_id"]))

    assert report["calls"]["connections_opened"] == 1
    assert report["calls"]["connections_closed"] == 1
    assert report["calls"]["short_connections"] == 1
    assert report["calls"]["zero_byte_connections"] == 1


def test_report_separates_selected_testers_from_other_calls_users(tmp_path) -> None:
    clock = _Clock()
    runtime = _runtime(tmp_path, clock)
    service = CallsTelemetryService(runtime)
    state = _state()
    started = service.start(state, ["alpha@example.com"], sample_interval_seconds=2)
    state.install["traffic_connection_counters"] = {
        "selected": {
            "protocol": "calls", "user": "alpha@example.com",
            "upload": 0, "download": 0, "missed_polls": 0,
        },
        "other": {
            "protocol": "calls", "user": "bravo@example.com",
            "upload": 0, "download": 0, "missed_polls": 0,
        },
    }
    runtime.record(state)
    state.install["traffic_connection_counters"]["selected"]["upload"] = 100
    state.install["traffic_connection_counters"]["other"]["upload"] = 300
    clock.value += 2
    runtime.record(state)

    report = service.report(str(started["session_id"]))

    assert report["calls"]["tester_traffic_ratio"] == 0.25
    assert report["calls"]["other_user_bytes"] == 300
    assert "experiment_traffic_contamination" in {
        finding["code"] for finding in report["findings"]
    }


def test_goodput_correlations_cover_process_queue_kcp_and_client_loss() -> None:
    samples = []
    cumulative_ticks = 0
    for index in range(5):
        cumulative_ticks += index * 10
        samples.append({
            "timestamp": float(index),
            "calls": {
                "interval": {"upload_bytes": index * 100, "download_bytes": 0},
                "active_connections": index,
            },
            "host": {"cpu_percent": index * 10},
            "runtime": {
                "cpu_ticks": cumulative_ticks,
                "clock_ticks_per_second": 100,
            },
            "udp": {"listener_rx_queue_bytes": index * 10},
            "native": {"latest": {
                "server": {
                    "kcp_wait_snd": index * 10,
                    "kcp_rtt_ms": index * 10,
                    "kcp_output_queue_depth": index * 10,
                    "lane_admission_window_segments": index * 10,
                    "worker_write_latency_ms": index * 10,
                },
                "clients": {"tester-1": {"network_loss_ratio": index / 10}},
            }},
        })

    correlations = throughput_correlations(samples)

    assert correlations["hydracore_cpu_percent"] == {
        "pearson_r": 1.0,
        "samples": 4,
    }
    assert correlations["kcp_wait_snd"]["pearson_r"] == 1.0
    assert correlations["kcp_output_queue_depth"]["pearson_r"] == 1.0
    assert correlations["lane_admission_window_segments"]["samples"] == 4
    assert correlations["worker_write_latency_ms"]["samples"] == 4
    assert correlations["network_loss_ratio"]["samples"] == 4
