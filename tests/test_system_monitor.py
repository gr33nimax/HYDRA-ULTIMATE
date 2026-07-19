from hydra.ui.system_monitor import read_proc_cpu, read_proc_mem, read_proc_net


def test_read_proc_cpu(tmp_path):
    stat = tmp_path / "stat"
    stat.write_text("cpu  10 2 3 40 5 6 7 8\n", encoding="utf-8")

    assert read_proc_cpu(stat) == (45.0, 73.0)


def test_read_proc_mem_uses_available(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal: 1000 kB\nMemAvailable: 250 kB\n",
        encoding="utf-8",
    )

    used, total, percent = read_proc_mem(meminfo)

    assert (used, total) == (750 * 1024, 1000 * 1024)
    assert percent == 75.0


def test_read_proc_mem_supports_legacy_kernel_fields(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\n"
        "Cached: 200 kB\nSReclaimable: 25 kB\nShmem: 25 kB\n",
        encoding="utf-8",
    )

    used, _, percent = read_proc_mem(meminfo)

    assert used == 650 * 1024
    assert percent == 65.0


def test_read_proc_net_uses_default_route_interface(tmp_path):
    route = tmp_path / "route"
    route.write_text(
        "Iface Destination Gateway Flags\neth0 00000000 00000000 0003\n",
        encoding="utf-8",
    )
    dev = tmp_path / "dev"
    dev.write_text(
        "Inter-| Receive | Transmit\n face |bytes |bytes\n"
        "lo: 1 0 0 0 0 0 0 0 2 0\n"
        "eth0: 100 0 0 0 0 0 0 0 200 0\n"
        "wg0: 300 0 0 0 0 0 0 0 400 0\n",
        encoding="utf-8",
    )

    assert read_proc_net(route, dev) == (100, 200)
