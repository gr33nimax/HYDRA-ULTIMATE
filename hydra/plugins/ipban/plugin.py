"""
hydra/plugins/ipban/plugin.py — IP-бан: ручная блокировка IP/CIDR/ASN через ipset.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import shlex
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
_RULE_COMMENT = "hydra-ipban"


def _rule_spec(ipset_name: str) -> list[str]:
    return [
        "-m", "set", "--match-set", ipset_name, "src",
        "-m", "comment", "--comment", _RULE_COMMENT,
        "-j", "DROP",
    ]


def _run(command: list[str], *, text: bool = False, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=text, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 1, stdout="" if text else b"", stderr=str(exc))


class IPBanPlugin(BasePlugin):
    meta = PluginMeta(
        name="ipban",
        description="IP-бан: ручная блокировка IP/CIDR/диапазона/ASN через ipset",
        category=PluginCategory.SECURITY,
        version="2.1.0",
    )

    def install(self) -> bool:
        if not self._installed():
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
            
        return self._ensure_sets() and self._ensure_iptables_rules()

    def uninstall(self) -> bool:
        rules_removed = self._remove_iptables_rules()
        if not rules_removed:
            return False
        if self._installed():
            for name in (IPSET_V4, IPSET_V6):
                _run(["ipset", "flush", name])
                _run(["ipset", "destroy", name])
        STATE_FILE.unlink(missing_ok=True)
        return True

    def _installed(self) -> bool:
        return all(shutil.which(binary) is not None for binary in ("ipset", "iptables", "ip6tables"))

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        return self._ensure_sets() and self._ensure_iptables_rules() and self._restore_from_state()

    def status(self) -> PluginStatus:
        if not self._installed():
            return PluginStatus(installed=False, enabled=False, running=False)
        state = self._load_state()
        entries = state.get("entries", [])
        v4, v6 = self._ipset_count()
        rules_present = self._iptables_rules_present()
        return PluginStatus(
            installed=True,
            enabled=rules_present,
            running=rules_present,
            info={"entries": len(entries), "cidrs_v4": v4, "cidrs_v6": v6},
        )

    def ban_ip(self, raw: str, comment: str = "") -> bool:
        if not self._ensure_sets() or not self._ensure_iptables_rules():
            return False
        try:
            display, kind, cidrs = self._resolve_to_cidrs(raw)
        except (ValueError, RuntimeError) as e:
            return False
        v4 = [c for c in cidrs if ":" not in c]
        v6 = [c for c in cidrs if ":" in c]
        added: list[tuple[str, str]] = []
        for set_name, values in ((IPSET_V4, v4), (IPSET_V6, v6)):
            for cidr in values:
                existed = _run(["ipset", "test", set_name, cidr]).returncode == 0
                result = _run(["ipset", "add", set_name, cidr, "-exist"])
                if result.returncode != 0:
                    for rollback_set, rollback_cidr in added:
                        _run(["ipset", "del", rollback_set, rollback_cidr])
                    return False
                if not existed:
                    added.append((set_name, cidr))
        self._state_add_entry(display, cidrs, kind, comment)
        return True

    def unban_ip(self, display: str) -> bool:
        if not self._installed():
            return False
        state = self._load_state()
        entry = next((e for e in state.get("entries", []) if e.get("display") == display), None)
        if not entry:
            return False
        remaining = [e for e in state.get("entries", []) if e.get("display") != display]
        still_referenced = {
            cidr for other in remaining for cidr in other.get("cidrs", [])
        }
        ok = True
        for cidr in entry.get("cidrs", []):
            if cidr in still_referenced:
                continue
            if ":" not in cidr:
                result = _run(["ipset", "del", IPSET_V4, cidr])
            else:
                result = _run(["ipset", "del", IPSET_V6, cidr])
            # Missing members are already unbanned; other failures must not be
            # hidden by deleting the database entry.
            stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else str(result.stderr or "")
            if result.returncode != 0 and "not in set" not in stderr.lower():
                ok = False
        if not ok:
            return False
        state["entries"] = remaining
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

    def _ensure_sets(self) -> bool:
        if not self._installed():
            return False
        for name, family in [(IPSET_V4, "inet"), (IPSET_V6, "inet6")]:
            result = _run(["ipset", "create", name, "hash:net", "family", family, "maxelem", "65536", "-exist"])
            if result.returncode != 0:
                return False
        return True

    def _ensure_iptables_rules(self) -> bool:
        for binary, ipset_name in (("iptables", IPSET_V4), ("ip6tables", IPSET_V6)):
            spec = _rule_spec(ipset_name)
            check = _run([binary, "-C", "INPUT", *spec])
            if check.returncode != 0:
                inserted = _run([binary, "-I", "INPUT", "1", *spec])
                if inserted.returncode != 0:
                    return False
        return self._iptables_rules_present()

    def _iptables_rules_present(self) -> bool:
        return all(
            _run([binary, "-C", "INPUT", *_rule_spec(ipset_name)]).returncode == 0
            for binary, ipset_name in (("iptables", IPSET_V4), ("ip6tables", IPSET_V6))
        )

    def _remove_iptables_rules(self) -> bool:
        ok = True
        for binary, ipset_name in (("iptables", IPSET_V4), ("ip6tables", IPSET_V6)):
            listed = _run([binary, "-S", "INPUT"], text=True)
            if listed.returncode != 0:
                ok = False
                continue
            for line in listed.stdout.splitlines():
                if _RULE_COMMENT not in line and ipset_name not in line:
                    continue
                try:
                    parts = shlex.split(line)
                except ValueError:
                    ok = False
                    continue
                if not parts or parts[0] != "-A":
                    continue
                parts[0] = "-D"
                if _run([binary, *parts]).returncode != 0:
                    ok = False

        # Migration cleanup for the historical bug that attached the IPv6 set
        # to the IPv4 table as well.
        listed_v4 = _run(["iptables", "-S", "INPUT"], text=True)
        for line in listed_v4.stdout.splitlines() if listed_v4.returncode == 0 else []:
            if IPSET_V6 not in line:
                continue
            parts = shlex.split(line)
            if parts and parts[0] == "-A":
                parts[0] = "-D"
                if _run(["iptables", *parts]).returncode != 0:
                    ok = False
        return ok

    def _ipset_count(self) -> tuple[int, int]:
        def _cnt(name):
            r = _run(["ipset", "list", name], text=True)
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
        temporary = STATE_FILE.with_name(f".{STATE_FILE.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            temporary.replace(STATE_FILE)
        finally:
            temporary.unlink(missing_ok=True)

    def _state_add_entry(self, display: str, cidrs: list[str], kind: str, comment: str = "") -> None:
        state = self._load_state()
        state["entries"] = [e for e in state["entries"] if e.get("display") != display]
        state["entries"].append({
            "display": display, "kind": kind, "cidrs": cidrs,
            "comment": comment,
            "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        self._save_state(state)

    def _restore_from_state(self) -> bool:
        if not self._installed():
            return False
        state = self._load_state()
        for e in state.get("entries", []):
            for cidr in e.get("cidrs", []):
                if ":" not in cidr:
                    result = _run(["ipset", "add", IPSET_V4, cidr, "-exist"])
                else:
                    result = _run(["ipset", "add", IPSET_V6, cidr, "-exist"])
                if result.returncode != 0:
                    return False
        return True

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        if not self.apply(state):
            raise RuntimeError("IPBan firewall rules could not be installed")

    def on_disable(self, state: AppState) -> None:
        if not self._installed():
            return
        if not self._remove_iptables_rules():
            raise RuntimeError("IPBan firewall rules could not be removed")
        _run(["ipset", "flush", IPSET_V4])
        _run(["ipset", "flush", IPSET_V6])
