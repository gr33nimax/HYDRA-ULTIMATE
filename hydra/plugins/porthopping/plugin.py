"""hydra/plugins/porthopping/plugin.py — Port Hopping: диапазон портов → реальный порт через nftables.

Контракт v2 — ENHANCEMENT:
  • configure() — пустой фрагмент (не влияет на sing-box).
  • apply() — ставит nftables PREROUTING REDIRECT для диапазона портов.
  • iptables заменён на nftables (встроен в ядро, единый синтаксис).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

NFT_TABLE = "hydra-porthopping"
DEFAULT_RANGE_START = 10000
DEFAULT_RANGE_END = 20000
DEFAULT_REAL_PORT = 443
DEFAULT_PROTO = "tcp"


class PortHoppingPlugin(BasePlugin):
    meta = PluginMeta(
        name="porthopping",
        description="Port Hopping: приём подключений на диапазон портов через nftables",
        category=PluginCategory.ENHANCEMENT,
        version="2.0.0",
    )

    # ═════════════════════════════════════════════════════════════════════
    #  configure — пустой фрагмент (нет вклада в sing-box config)
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        ps = state.protocols.get("porthopping")
        cfg = ps.config if ps and ps.config else {}

        if not cfg.get("enabled", False):
            self._clear_rules()
            return True

        range_start = cfg.get("range_start", DEFAULT_RANGE_START)
        range_end = cfg.get("range_end", DEFAULT_RANGE_END)
        real_port = cfg.get("real_port", DEFAULT_REAL_PORT)
        proto = cfg.get("proto", DEFAULT_PROTO)

        return self._apply_rules(range_start, range_end, real_port, proto)

    def _apply_rules(self, range_start: int, range_end: int, real_port: int, proto: str) -> bool:
        self._clear_rules()

        nft_script = f"""
add table inet {NFT_TABLE}

define range_start = {range_start}
define range_end = {range_end}
define real_port = {real_port}

add chain inet {NFT_TABLE} prerouting {{
    type nat hook prerouting priority 0; policy accept;
}}
"""
        protos = ["tcp", "udp"] if proto == "both" else [proto]
        for p in protos:
            nft_script += (
                f"add rule inet {NFT_TABLE} prerouting "
                f"meta l4proto {p} "
                f"th dport $range_start-$range_end "
                f"redirect to :$real_port comment \\\"hydra-porthopping\\\"\n"
            )

        r = subprocess.run(
            ["nft", "-f", "-"], input=nft_script, text=True,
            capture_output=True,
        )
        if r.returncode != 0:
            print(f"  nftables error: {(r.stderr or '')[:300]}")
            return False

        self._persist()
        return True

    def _clear_rules(self) -> None:
        subprocess.run(
            ["nft", "delete", "table", "inet", NFT_TABLE],
            capture_output=True,
        )

    @staticmethod
    def _persist() -> None:
        """nft list ruleset > /etc/nftables.conf"""
        r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout:
            try:
                Path("/etc/nftables.conf").write_text(r.stdout)
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        return self._nft_available()

    def uninstall(self) -> bool:
        self._clear_rules()
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Статус
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        available = self._nft_available()
        running = False
        r = subprocess.run(
            ["nft", "list", "table", "inet", NFT_TABLE],
            capture_output=True, text=True,
        )
        running = r.returncode == 0 and "hydra-porthopping" in r.stdout

        return PluginStatus(
            installed=available,
            enabled=running,
            running=running,
        )

    # ═════════════════════════════════════════════════════════════════════
    #  Управление
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.apply(state)

    def on_disable(self, state: AppState) -> None:
        self._clear_rules()

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _nft_available() -> bool:
        r = subprocess.run(["nft", "--version"], capture_output=True)
        return r.returncode == 0

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}
