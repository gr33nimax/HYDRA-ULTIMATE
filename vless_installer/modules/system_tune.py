"""
Sysctl/limits network tuning for HYDRA.
Extracted from vless_installer/_core.py (Phase 4).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import threading
from datetime import datetime
from pathlib import Path


class _LazyCore:
    """Late-bind to vless_installer._core (avoids circular import at load time)."""
    _mod = None

    def _m(self):
        if self._mod is None:
            import vless_installer._core as m
            self._mod = m
        return self._mod

    def __getattr__(self, name: str):
        return getattr(self._m(), name)


core = _LazyCore()


def apply_network_optimizations() -> None:
    core.info(f"Оптимизация сетевого стека (RAM: {core.TOTAL_RAM}MB)...")
    core.PROGRESS.update(2, "Оптимизация")

    overcommit = core.get_adaptive_value("overcommit") or "1"
    swappiness  = core.get_adaptive_value("swappiness") or "10"
    conntrack   = core.get_adaptive_value("conntrack")  or "1048576"
    file_max    = core.get_adaptive_value("file_max")   or "2097152"

    # BBR detection
    try:
        kernel_ver = core._run(["uname", "-r"], capture=True, check=False).stdout.strip()
        parts = kernel_ver.split(".")
        k_major = int(re.match(r'^(\d+)', parts[0]).group(1)) if parts else 4
        k_minor = int(re.match(r'^(\d+)', parts[1]).group(1)) if len(parts) > 1 else 0
    except Exception:
        k_major, k_minor = 4, 0

    bbr_available = False
    if k_major > 4 or (k_major == 4 and k_minor >= 9):
        core._run(["modprobe", "tcp_bbr"], check=False, quiet=True)
        r = core._run(["sysctl", "net.ipv4.tcp_available_congestion_control"],
                 capture=True, check=False)
        if "bbr" in r.stdout:
            bbr_available = True

    congestion_lines = (
        "net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n"
        if bbr_available else
        "net.ipv4.tcp_congestion_control = cubic\n"
    )

    sysctl_content = textwrap.dedent(f"""\
        # =============================================================
        #  Сетевые оптимизации для HYDRA (NaiveProxy / Mieru / AWG)
        #  Адаптировано под: {core.TOTAL_RAM}MB RAM, {core.TOTAL_CPU} CPU
        # =============================================================
        {congestion_lines}net.ipv4.tcp_fastopen = 3
        net.core.rmem_max = 134217728
        net.core.wmem_max = 134217728
        net.core.rmem_default = 1048576
        net.core.wmem_default = 1048576
        net.ipv4.tcp_rmem = 4096 1048576 134217728
        net.ipv4.tcp_wmem = 4096 1048576 134217728
        net.ipv4.tcp_mem = 786432 1048576 26777216
        net.core.optmem_max = 65536
        net.ipv4.tcp_moderate_rcvbuf = 1
        net.core.netdev_budget = 600
        net.core.somaxconn = 65535
        net.ipv4.tcp_max_syn_backlog = 65535
        net.core.netdev_max_backlog = 250000
        net.netfilter.nf_conntrack_max = {conntrack}
        net.ipv4.ip_local_port_range = 1024 65535
        net.ipv4.tcp_tw_reuse = 1
        net.ipv4.tcp_max_tw_buckets = 2000000
        net.ipv4.tcp_slow_start_after_idle = 0
        net.ipv4.tcp_sack = 1
        net.ipv4.tcp_ecn = 1
        net.ipv4.tcp_mtu_probing = 1
        net.ipv4.tcp_keepalive_time = 600
        net.ipv4.tcp_keepalive_intvl = 60
        net.ipv4.tcp_keepalive_probes = 6
        net.ipv4.tcp_fin_timeout = 30
        # HYDRA: AWG/Mieru/подписки требуют маршрутизации
        net.ipv4.ip_forward = 1
        net.ipv6.conf.all.disable_ipv6 = 0
        net.ipv6.conf.default.disable_ipv6 = 0
        net.ipv6.conf.lo.disable_ipv6 = 0
        net.ipv6.conf.all.accept_ra = 2
        net.ipv6.conf.default.accept_ra = 2
        net.ipv6.conf.all.forwarding = 1
        net.ipv6.conf.all.use_tempaddr = 2
        net.ipv6.conf.default.use_tempaddr = 2
        net.ipv6.conf.all.temp_prefered_lft = 86400
        net.ipv6.conf.all.temp_valid_lft = 604800
        net.ipv6.conf.all.hop_limit = 128
        net.ipv6.neigh.default.gc_thresh1 = 512
        net.ipv6.neigh.default.gc_thresh2 = 2048
        net.ipv6.neigh.default.gc_thresh3 = 4096
        net.ipv6.flowlabel_consistency = 1
        net.ipv6.flowlabel_state_ranges = 1
        net.ipv6.conf.all.accept_redirects = 0
        net.ipv6.conf.default.accept_redirects = 0
        net.ipv6.conf.all.drop_unsolicited_na = 1
        net.ipv6.conf.default.drop_unsolicited_na = 1
        net.ipv6.conf.all.accept_dad = 1
        net.ipv6.conf.default.accept_dad = 1
        net.ipv6.conf.all.accept_source_route = 0
        net.ipv6.conf.default.accept_source_route = 0
        net.ipv4.udp_mem = 786432 1048576 26214400
        net.ipv4.udp_rmem_min = 16384
        net.ipv4.udp_wmem_min = 16384
        net.ipv4.tcp_syncookies = 1
        net.ipv4.tcp_window_scaling = 1
        net.ipv4.tcp_timestamps = 1
        net.ipv4.tcp_syn_retries = 3
        net.ipv4.tcp_synack_retries = 3
        fs.file-max = {file_max}
        fs.nr_open = 2097152
        vm.overcommit_memory = {overcommit}
        vm.swappiness = {swappiness}
        vm.dirty_ratio = 15
        vm.dirty_background_ratio = 5
        kernel.numa_balancing = 1
        kernel.sched_min_granularity_ns = 10000000
        kernel.sched_wakeup_granularity_ns = 15000000
        kernel.panic = 10
        kernel.panic_on_oops = 1
    """)

    core.OPTIMIZER_CONF.parent.mkdir(parents=True, exist_ok=True)
    core.OPTIMIZER_CONF.write_text(sysctl_content)
    core._run(["sysctl", "-p", str(core.OPTIMIZER_CONF)], check=False, quiet=True)

    core.LIMITS_CONF.parent.mkdir(parents=True, exist_ok=True)
    core.LIMITS_CONF.write_text(textwrap.dedent("""\
        * soft nofile 1048576
        * hard nofile 1048576
        * soft nproc  unlimited
        * hard nproc  unlimited
        root soft nofile 1048576
        root hard nofile 1048576
        root soft nproc  unlimited
        root hard nproc  unlimited
    """))

    core.SYSTEMD_CONF.parent.mkdir(parents=True, exist_ok=True)
    core.SYSTEMD_CONF.write_text(textwrap.dedent("""\
        [Manager]
        DefaultLimitNOFILE=1048576
        DefaultLimitNPROC=infinity
    """))
    core._run(["systemctl", "daemon-reexec"], check=False, quiet=True)

    thp = Path("/sys/kernel/mm/transparent_hugepage/enabled")
    if thp.exists():
        try:
            thp.write_text("madvise")
        except Exception:
            pass

    if core.command_exists("irqbalance"):
        core._run(["systemctl", "enable", "--now", "irqbalance"], check=False, quiet=True)
        core.success("irqbalance запущен")

    if bbr_available:
        r = core._run(["ip", "-o", "link", "show"], capture=True, check=False)
        ifaces = [
            m.group(1) for line in r.stdout.splitlines()
            if (m := re.match(r'\d+:\s+(\S+):', line)) and m.group(1) != "lo"
        ]
        for iface in ifaces:
            core._run(["tc", "qdisc", "replace", "dev", iface, "root", "fq"],
                 check=False, quiet=True)
        try:
            with open("/etc/modules-load.d/bbr.conf", "a") as f:
                f.write("tcp_bbr\n")
        except Exception:
            pass
        core.success("BBR активирован + fq планировщик")
    else:
        core.info(f"BBR недоступен на ядре {k_major}.{k_minor}, используется cubic")

    core._run(["modprobe", "nf_conntrack"], check=False, quiet=True)
    hashsize = Path("/sys/module/nf_conntrack/parameters/hashsize")
    if hashsize.exists():
        try:
            hashsize.write_text("131072")
        except Exception:
            pass

    core.PROGRESS.update(3, "Оптимизация")
    core.success(f"Сетевой стек оптимизирован (адаптивно под {core.TOTAL_RAM}MB RAM)")
def apply_sysctl_and_limits() -> None:
    """Применяет настройки sysctl и limits.conf для оптимизации производительности."""
    sysctl_conf = core.OPTIMIZER_CONF
    limits_conf = core.LIMITS_CONF
    applied = False

    # Если файлов оптимизации нет, сгенерируем их
    if not sysctl_conf.exists() or not limits_conf.exists():
        core.info("Конфигурационные файлы оптимизации не найдены. Генерируем...")
        core.PROGRESS.init(100, "Оптимизация")
        apply_network_optimizations()
        core.PROGRESS.update(100 - core.PROGRESS.current, "Готово")

    if sysctl_conf.exists():
        r = core._run(["sysctl", "--system"], check=False, quiet=False)
        if r.returncode == 0:
            core.success(f"sysctl применён из {sysctl_conf}")
            applied = True
        else:
            core.warn("Ошибка применения sysctl")
    else:
        core.warn(f"Файл {sysctl_conf} не найден — запустите установку (п.1)")
    if limits_conf.exists():
        core.success(f"limits.conf готов: {limits_conf}")
        applied = True
    if not applied:
        core.warn("Файлы оптимизации не найдены. Сначала выполните установку (п.1).")
