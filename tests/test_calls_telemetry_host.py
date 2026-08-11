from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from hydra.services.calls_telemetry_host import (
    collect_kernel_metrics,
    collect_runtime_metrics,
    collect_udp_metrics,
)


class _Host:
    def run(self, command, **kwargs):
        assert command[:3] == ["systemctl", "show", "sing-box"]
        assert kwargs["timeout"] == 3
        return SimpleNamespace(
            returncode=0,
            stdout="MainPID=123\nNRestarts=2\nActiveState=active\n",
        )


def test_runtime_metrics_read_the_managed_sing_box_process(tmp_path: Path) -> None:
    process = tmp_path / "123"
    process.mkdir()
    fields = ["0"] * 22
    fields[0] = "S"
    fields[11] = "100"
    fields[12] = "50"
    fields[21] = "10"
    (process / "stat").write_text(
        "123 (sing-box worker) " + " ".join(fields),
        encoding="utf-8",
    )

    metrics = collect_runtime_metrics(
        _Host(),
        tmp_path,
        page_size=4096,
        clock_ticks_per_second=100,
    )

    assert metrics["active"] is True
    assert metrics["pid"] == 123
    assert metrics["restarts"] == 2
    assert metrics["cpu_ticks"] == 150
    assert metrics["clock_ticks_per_second"] == 100
    assert metrics["rss_bytes"] == 10 * 4096
    assert metrics["threads"] == 0
    assert metrics["open_fds"] == 0


def test_udp_metrics_separate_host_errors_from_calls_listener_drops(tmp_path: Path) -> None:
    network = tmp_path / "net"
    network.mkdir()
    (network / "snmp").write_text(
        "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n"
        "Udp: 100 2 3 200 4 5\n",
        encoding="utf-8",
    )
    (network / "udp").write_text(
        "header\n"
        "1: 00000000:DAC2 00000000:0000 07 00000000:00000020 x x x x x 7\n",
        encoding="utf-8",
    )
    (network / "udp6").write_text("header\n", encoding="utf-8")

    metrics = collect_udp_metrics(tmp_path, 56002)

    assert metrics["in_errors"] == 3
    assert metrics["receive_buffer_errors"] == 4
    assert metrics["send_buffer_errors"] == 5
    assert metrics["listener_rx_queue_bytes"] == 32
    assert metrics["listener_drops"] == 7


def test_kernel_metrics_capture_pressure_backlog_nic_and_conntrack(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    (proc / "pressure").mkdir(parents=True)
    (proc / "net").mkdir()
    (proc / "sys/net/netfilter").mkdir(parents=True)
    for name in ("cpu", "memory", "io"):
        (proc / "pressure" / name).write_text(
            "some avg10=1.25 avg60=0.50 avg300=0.10 total=1000\n",
            encoding="utf-8",
        )
    (proc / "net/softnet_stat").write_text(
        "00000010 00000002 00000003 0 0 0 0 0 0 0 0\n",
        encoding="utf-8",
    )
    (proc / "net/dev").write_text(
        "header\nheader\n"
        "eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
        encoding="utf-8",
    )
    (proc / "stat").write_text(
        "ctxt 100\nprocesses 20\nprocs_running 2\nprocs_blocked 1\nintr 300 0\n",
        encoding="utf-8",
    )
    (proc / "meminfo").write_text(
        "SwapTotal: 10 kB\nSwapFree: 8 kB\nDirty: 2 kB\nWriteback: 1 kB\n",
        encoding="utf-8",
    )
    (proc / "sys/net/netfilter/nf_conntrack_count").write_text("10\n")
    (proc / "sys/net/netfilter/nf_conntrack_max").write_text("100\n")

    metrics = collect_kernel_metrics(proc, tmp_path)

    assert metrics["pressure"]["cpu"]["some"]["avg10"] == 1.25
    assert metrics["softnet"]["dropped"] == 2
    assert metrics["softnet"]["time_squeeze"] == 3
    assert metrics["interfaces"]["rx_drops"] == 2
    assert metrics["interfaces"]["tx_drops"] == 4
    assert metrics["conntrack"] == {"count": 10, "max": 100}
    assert metrics["memory"]["dirty_bytes"] == 2048
