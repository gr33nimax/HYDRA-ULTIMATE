"""
hydra/plugins/ipban/plugin.py — IP-бан: ручная блокировка IP/CIDR/ASN через ipset.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

IPSET_V4 = "hydra_manual_ban"
IPSET_V6 = "hydra_manual_ban6"
STATE_FILE = Path("/var/lib/hydra/ipban.json")
RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"


class IPBanPlugin(BasePlugin):
    meta = PluginMeta(
        name="ipban",
        description="IP-бан: ручная блокировка IP/CIDR/диапазона/ASN через ipset",
        category=PluginCategory.SECURITY,
        version="2.0.0",
    )

    def install(self) -> bool:
        if not self._installed():
            import shutil
            import os
            from hydra.utils.logging import error as log_error, info as log_info
            
            log_info("Starting ipset installation...")
            if shutil.which("apt-get"):
                env = dict(os.environ)
                env["DEBIAN_FRONTEND"] = "noninteractive"
                subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
                r = subprocess.run(["apt-get", "install", "-y", "-qq", "ipset"], capture_output=True, text=True, timeout=180, env=env)
                if r.returncode != 0:
                    log_error(f"apt-get install ipset failed (code {r.returncode}). Stderr: {r.stderr.strip()}")
            elif shutil.which("dnf"):
                r = subprocess.run(["dnf", "install", "-y", "-q", "ipset"], capture_output=True, text=True, timeout=180)
                if r.returncode != 0:
                    log_error(f"dnf install ipset failed. Stderr: {r.stderr.strip()}")
            elif shutil.which("yum"):
                r = subprocess.run(["yum", "install", "-y", "-q", "ipset"], capture_output=True, text=True, timeout=180)
                if r.returncode != 0:
                    log_error(f"yum install ipset failed. Stderr: {r.stderr.strip()}")
            elif shutil.which("apk"):
                r = subprocess.run(["apk", "add", "--no-cache", "ipset"], capture_output=True, text=True, timeout=180)
                if r.returncode != 0:
                    log_error(f"apk add ipset failed. Stderr: {r.stderr.strip()}")
            elif shutil.which("pacman"):
                r = subprocess.run(["pacman", "-Sy", "--noconfirm", "ipset"], capture_output=True, text=True, timeout=180)
                if r.returncode != 0:
                    log_error(f"pacman install ipset failed. Stderr: {r.stderr.strip()}")
                    
        if not self._installed():
            return False
            
        self._ensure_sets()
        self._ensure_iptables_rules()
        return True

    def uninstall(self) -> bool:
        self._remove_iptables_rules()
        if self._installed():
            subprocess.run(["ipset", "flush", IPSET_V4], capture_output=True)
            subprocess.run(["ipset", "flush", IPSET_V6], capture_output=True)
            subprocess.run(["ipset", "destroy", IPSET_V4], capture_output=True)
            subprocess.run(["ipset", "destroy", IPSET_V6], capture_output=True)
        STATE_FILE.unlink(missing_ok=True)
        return True

    def _installed(self) -> bool:
        import shutil
        return shutil.which("ipset") is not None

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        self._ensure_sets()
        self._ensure_iptables_rules()
        self._restore_from_state()
        return True

    def status(self) -> PluginStatus:
        if not self._installed():
            return PluginStatus(installed=False, enabled=False, running=False)
        state = self._load_state()
        entries = state.get("entries", [])
        v4, v6 = self._ipset_count()
        return PluginStatus(
            installed=True,
            enabled=len(entries) > 0,
            running=True,
            info={"entries": len(entries), "cidrs_v4": v4, "cidrs_v6": v6},
        )

    def ban_ip(self, raw: str, comment: str = "") -> bool:
        self._ensure_sets()
        self._ensure_iptables_rules()
        try:
            display, kind, cidrs = self._resolve_to_cidrs(raw)
        except (ValueError, RuntimeError) as e:
            return False
        v4 = [c for c in cidrs if ":" not in c]
        v6 = [c for c in cidrs if ":" in c]
        for c in v4:
            subprocess.run(["ipset", "add", IPSET_V4, c, "-exist"], capture_output=True)
        for c in v6:
            subprocess.run(["ipset", "add", IPSET_V6, c, "-exist"], capture_output=True)
        self._state_add_entry(display, cidrs, kind, comment)
        return True

    def unban_ip(self, display: str) -> bool:
        if not self._installed():
            return False
        state = self._load_state()
        entry = next((e for e in state.get("entries", []) if e.get("display") == display), None)
        if not entry:
            return False
        for cidr in entry.get("cidrs", []):
            if ":" not in cidr:
                subprocess.run(["ipset", "del", IPSET_V4, cidr], capture_output=True)
            else:
                subprocess.run(["ipset", "del", IPSET_V6, cidr], capture_output=True)
        state["entries"] = [e for e in state["entries"] if e.get("display") != display]
        self._save_state(state)
        return True

    def list_banned(self) -> list[dict]:
        state = self._load_state()
        return state.get("entries", [])

    def _resolve_to_cidrs(self, raw: str) -> tuple[str, str, list[str]]:
        raw = raw.strip()
        up = raw.upper()
        if up.startswith("AS") or (raw.isdigit() and len(raw) <= 10):
            asn = raw if raw.upper().startswith("AS") else f"AS{raw}"
            cidrs = self._fetch_asn_prefixes(asn)
            return asn, "asn", cidrs
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net), "cidr", [str(net)]
        if "-" in raw and ":" not in raw:
            parts = raw.split("-", 1)
            start = ipaddress.IPv4Address(parts[0].strip())
            end = ipaddress.IPv4Address(parts[1].strip())
            if start > end:
                start, end = end, start
            cidrs = [str(n) for n in ipaddress.summarize_address_range(start, end)]
            return raw, "range", cidrs
        net = ipaddress.ip_address(raw)
        bits = 32 if net.version == 4 else 128
        return str(net), "ip", [f"{net}/{bits}"]

    def _fetch_asn_prefixes(self, asn: str) -> list[str]:
        url = RIPE_URL.format(asn=asn)
        for attempt in range(1, 4):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "hydra/2.0", "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                break
            except Exception:
                if attempt == 3:
                    raise RuntimeError(f"RIPE Stat недоступен для {asn}")
                time.sleep(2 ** attempt)
        prefixes = data.get("data", {}).get("prefixes", [])
        result = []
        for item in prefixes:
            p = item.get("prefix", "")
            try:
                net = ipaddress.ip_network(p, strict=False)
                result.append(str(net))
            except ValueError:
                continue
        if not result:
            raise RuntimeError(f"0 префиксов для {asn}")
        return result

    def _ensure_sets(self) -> None:
        if not self._installed():
            return
        for name, family in [(IPSET_V4, "inet"), (IPSET_V6, "inet6")]:
            subprocess.run(["ipset", "create", name, "hash:net", "family", family, "maxelem", "65536", "-exist"], capture_output=True)

    def _ensure_iptables_rules(self) -> None:
        for ipset_name in (IPSET_V4, IPSET_V6):
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"], capture_output=True)
            if check.returncode != 0:
                subprocess.run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP", "-m", "comment", "--comment", "hydra-ipban"], capture_output=True)
        check6 = subprocess.run(["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], capture_output=True)
        if check6.returncode != 0:
            subprocess.run(["ip6tables", "-A", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP", "-m", "comment", "--comment", "hydra-ipban"], capture_output=True)

    def _remove_iptables_rules(self) -> None:
        for _ in range(10):
            r = subprocess.run(["iptables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_V4, "src", "-j", "DROP"], capture_output=True)
            if r.returncode != 0:
                break
        for _ in range(10):
            r = subprocess.run(["ip6tables", "-D", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], capture_output=True)
            if r.returncode != 0:
                break

    def _ipset_count(self) -> tuple[int, int]:
        def _cnt(name):
            r = subprocess.run(["ipset", "list", name], capture_output=True, text=True)
            if "Members:" not in r.stdout:
                return 0
            after = r.stdout.split("Members:", 1)[1]
            return sum(1 for ln in after.splitlines() if ln.strip())
        return _cnt(IPSET_V4), _cnt(IPSET_V6)

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass
        return {"entries": []}

    def _save_state(self, data: dict) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def _state_add_entry(self, display: str, cidrs: list[str], kind: str, comment: str = "") -> None:
        state = self._load_state()
        state["entries"] = [e for e in state["entries"] if e.get("display") != display]
        state["entries"].append({
            "display": display, "kind": kind, "cidrs": cidrs,
            "comment": comment,
            "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        self._save_state(state)

    def _restore_from_state(self) -> None:
        if not self._installed():
            return
        state = self._load_state()
        for e in state.get("entries", []):
            for cidr in e.get("cidrs", []):
                if ":" not in cidr:
                    subprocess.run(["ipset", "add", IPSET_V4, cidr, "-exist"], capture_output=True)
                else:
                    subprocess.run(["ipset", "add", IPSET_V6, cidr, "-exist"], capture_output=True)

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        if not self._installed():
            return
        self._ensure_sets()
        self._ensure_iptables_rules()
        self._restore_from_state()

    def on_disable(self, state: AppState) -> None:
        if not self._installed():
            return
        self._remove_iptables_rules()
        subprocess.run(["ipset", "flush", IPSET_V4], capture_output=True)
        subprocess.run(["ipset", "flush", IPSET_V6], capture_output=True)
