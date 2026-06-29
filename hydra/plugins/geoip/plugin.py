"""
hydra/plugins/geoip/plugin.py — GeoIP блокировка входящих из РФ (nftables + ipset).
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

IPSET_V4 = "hydra_geoip_block"
IPSET_V6 = "hydra_geoip_block6"
STATE_FILE = Path("/var/lib/hydra/geoip.json")
RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=RU"


class GeoIPPlugin(BasePlugin):
    meta = PluginMeta(
        name="geoip",
        description="GeoIP: блокировка входящих из РФ на уровне nftables/ipset",
        category=PluginCategory.SECURITY,
        version="2.0.0",
    )

    def install(self) -> bool:
        if self._installed():
            return True
        subprocess.run(["apt-get", "install", "-y", "-qq", "ipset"], capture_output=True, timeout=120)
        return self._installed()

    def uninstall(self) -> bool:
        self._remove_rules()
        subprocess.run(["ipset", "destroy", IPSET_V4], capture_output=True)
        subprocess.run(["ipset", "destroy", IPSET_V6], capture_output=True)
        STATE_FILE.unlink(missing_ok=True)
        self._remove_iptables_rules()
        return True

    def _installed(self) -> bool:
        return subprocess.run(["which", "ipset"], capture_output=True).returncode == 0

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        self._ensure_sets()
        self._ensure_iptables_rules()
        v4, v6 = self._fetch_ru_subnets()
        if not v4:
            return False
        self._ipset_add_batch(v4, v6)
        self._save_state(len(v4), len(v6))
        return True

    def status(self) -> PluginStatus:
        if not self._installed():
            return PluginStatus(installed=False, enabled=False, running=False)
        state = self._load_state()
        enabled = state.get("enabled", False)
        v4_count, v6_count = self._ipset_count()
        return PluginStatus(
            installed=True,
            enabled=enabled,
            running=enabled,
            info={"cidrs_v4": v4_count, "cidrs_v6": v6_count},
        )

    def _fetch_ru_subnets(self) -> tuple[list[str], list[str]]:
        try:
            req = urllib.request.Request(RIPE_URL, headers={"User-Agent": "hydra/2.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception:
            return [], []
        prefixes = data.get("data", {}).get("prefixes", [])
        cidrs = []
        for item in prefixes:
            p = item.get("prefix", "")
            if p:
                cidrs.append(p)
        v4 = [c for c in cidrs if ":" not in c]
        v6 = [c for c in cidrs if ":" in c]
        return v4, v6

    def _ensure_sets(self) -> None:
        for name, family in [(IPSET_V4, "inet"), (IPSET_V6, "inet6")]:
            subprocess.run(["ipset", "create", name, "hash:net", "family", family, "maxelem", "500000", "-exist"], capture_output=True)

    def _ensure_iptables_rules(self) -> None:
        for ipset_name in (IPSET_V4, IPSET_V6):
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"], capture_output=True)
            if check.returncode != 0:
                subprocess.run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP", "-m", "comment", "--comment", "hydra-geoip"], capture_output=True)
        check6 = subprocess.run(["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], capture_output=True)
        if check6.returncode != 0:
            subprocess.run(["ip6tables", "-A", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP", "-m", "comment", "--comment", "hydra-geoip"], capture_output=True)

    def _remove_iptables_rules(self) -> None:
        for _ in range(10):
            r = subprocess.run(["iptables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_V4, "src", "-j", "DROP"], capture_output=True)
            if r.returncode != 0:
                break
        for _ in range(10):
            r = subprocess.run(["ip6tables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], capture_output=True)
            if r.returncode != 0:
                break

    def _ipset_add_batch(self, v4: list[str], v6: list[str]) -> None:
        for cidr in v4:
            subprocess.run(["ipset", "add", IPSET_V4, cidr, "-exist"], capture_output=True)
        for cidr in v6:
            subprocess.run(["ipset", "add", IPSET_V6, cidr, "-exist"], capture_output=True)

    def _ipset_count(self) -> tuple[int, int]:
        def _cnt(name):
            r = subprocess.run(["ipset", "list", name], capture_output=True, text=True)
            if "Members:" not in r.stdout:
                return 0
            after = r.stdout.split("Members:", 1)[1]
            return sum(1 for ln in after.splitlines() if ln.strip())
        return _cnt(IPSET_V4), _cnt(IPSET_V6)

    def _remove_rules(self) -> None:
        self._remove_iptables_rules()
        subprocess.run(["ipset", "flush", IPSET_V4], capture_output=True)
        subprocess.run(["ipset", "flush", IPSET_V6], capture_output=True)

    def _save_state(self, v4: int, v6: int) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({
            "enabled": True,
            "cidrs_v4": v4,
            "cidrs_v6": v6,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }))

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass
        return {}

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        self._ensure_sets()
        self._ensure_iptables_rules()
        v4, v6 = self._fetch_ru_subnets()
        if v4:
            self._ipset_add_batch(v4, v6)
            self._save_state(len(v4), len(v6))

    def on_disable(self, state: AppState) -> None:
        self._remove_rules()
        STATE_FILE.unlink(missing_ok=True)
