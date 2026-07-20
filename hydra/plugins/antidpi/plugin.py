"""Behavioural anti-DPI detector, deliberately independent from Fail2ban.

The detector consumes structured events from Caddy L4 (or any protocol
adapter), scores several weak signals, and bans only after a configurable
combination is observed.  It is intentionally conservative: a single
malformed packet never causes a ban.
"""
# audit: allow-generated-runtime-subprocess
from __future__ import annotations

import html
import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state import AppState
from hydra.plugins.base import BasePlugin, ConfigFragment, HealthResult, PluginCategory, PluginMeta, PluginStatus

STATE_FILE = Path("/var/lib/hydra/antidpi.json")
LOG_FILE = Path("/var/log/caddy-l4/antidpi.jsonl")
SCRIPT_FILE = Path("/usr/local/bin/hydra-antidpi.py")
SERVICE_FILE = Path("/etc/systemd/system/hydra-antidpi.service")
AWG_DEBUG_SERVICE = Path("/etc/systemd/system/hydra-awg-antidpi-debug.service")
AWG_DEBUG_PATHS = (Path("/sys/kernel/debug/dynamic_debug/control"), Path("/proc/dynamic_debug/control"))
SET_V4, SET_V6 = "hydra_antidpi", "hydra_antidpi6"
RULE_COMMENT = "hydra-antidpi"
SCAN_RULE_COMMENT = "hydra-antidpi-scan"
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Signals are protocol-independent.  A score is more robust than a single
# regex and keeps normal clients from being banned on one transient failure.
SIGNAL_WEIGHTS = {
    "malformed_tls": 4, "non_tls_on_tls": 3, "unknown_sni": 2,
    "handshake_failure": 2, "protocol_mismatch": 3, "quic_retry_burst": 2,
    "connection_burst": 2, "invalid_first_packet": 3,
    "active_decoy_probe": 8, "auth_failure": 3, "port_scan": 2,
    "port_sweep": 6,
}

SCORE_HALF_LIFE = 300.0
BAN_THRESHOLD = 8
BAN_DURATIONS = (600, 3600, 86400, 604800)  # 10m -> 1h -> 24h -> 7d
ALERT_COOLDOWN = 300.0
SCORE_RETENTION = 86400.0
MAX_SCORE_ENTRIES = 20000
DEFAULT_TRUSTED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))

LOCK_FILE = STATE_FILE.with_suffix(".lock")

try:
    import fcntl
except ImportError:
    fcntl = None


from contextlib import contextmanager

@contextmanager
def _lock_state_file():
    """File lock context manager using fcntl.flock to protect read-modify-write ops."""
    lock_path = STATE_FILE.with_suffix(".lock")
    if fcntl is not None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_path, "w", encoding="utf-8") as lock_fd:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
        except OSError as exc:
            raise RuntimeError(f"could not lock AntiDPI state: {exc}") from exc
    else:
        yield


_WHITELIST_CACHE: tuple[tuple[str, ...], list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = ((), [])


def _get_whitelisted_networks(raw_list: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    global _WHITELIST_CACHE
    current_raw = tuple(raw_list)
    if _WHITELIST_CACHE[0] == current_raw:
        return _WHITELIST_CACHE[1]
    parsed = []
    for raw in raw_list:
        try:
            parsed.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            continue
    _WHITELIST_CACHE = (current_raw, parsed)
    return parsed


def get_ban_duration(offense_count: int) -> int:
    """Return ban duration in seconds based on progressive offense count."""
    idx = min(max(0, offense_count - 1), len(BAN_DURATIONS) - 1)
    return BAN_DURATIONS[idx]


def active_bans(data: dict, *, now: float | None = None) -> dict:
    """Return only bans whose persisted timeout has not expired."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        return {}
    timestamp = time.time() if now is None else now
    result = {}
    for address, metadata in banned.items():
        if not isinstance(metadata, dict):
            continue
        try:
            expires_at = float(metadata.get("at", 0)) + int(metadata.get("duration", 86400))
        except (TypeError, ValueError):
            continue
        if timestamp < expires_at:
            result[address] = metadata
    return result



def prune_runtime_state(data: dict, *, now: float | None = None) -> None:
    """Bound per-address evidence while retaining active bans and recent scores."""
    scores = data.get("scores", {})
    if not isinstance(scores, dict):
        data["scores"] = {}
        return
    timestamp = time.time() if now is None else now
    active = set(active_bans(data, now=timestamp))
    retained = {}
    for address, metadata in scores.items():
        if not isinstance(metadata, dict):
            continue
        try:
            updated = float(metadata.get("updated", 0))
        except (TypeError, ValueError):
            continue
        if address in active or timestamp - updated <= SCORE_RETENTION:
            retained[address] = metadata
    if len(retained) > MAX_SCORE_ENTRIES:
        protected = {address: retained[address] for address in active if address in retained}
        candidates = sorted(
            ((address, metadata) for address, metadata in retained.items() if address not in protected),
            key=lambda item: float(item[1].get("updated", 0)),
            reverse=True,
        )
        available = max(0, MAX_SCORE_ENTRIES - len(protected))
        retained = {**protected, **dict(candidates[:available])}
    data["scores"] = retained


def _remote_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    else:
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError:
            raw = raw.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        return None


def normalize_caddy_record(record: dict) -> tuple[str, dict] | None:
    """Convert a caddy-l4 JSON log record into ``(ip, event)``.

    caddy-l4 has changed wording between releases, so matching is based on
    stable semantic fragments rather than one exact log line.
    """
    if not isinstance(record, dict):
        return None
    remote = str(record.get("remote", record.get("remote_ip", "")))
    if not remote:
        return None
    ip = _remote_ip(remote)
    if ip is None:
        return None
    text = " ".join(str(record.get(key, "")) for key in ("msg", "error", "err")) .lower()
    event = {"protocol": "tls", "handshake_ok": False}
    if any(token in text for token in ("no certificate", "unknown sni", "unrecognized server name")):
        event.update(kind="unknown_sni", sni_known=False)
    elif any(token in text for token in ("clienthello", "malformed", "record header", "unexpected message")):
        event["kind"] = "malformed_tls"
    elif any(token in text for token in ("eof", "handshake", "tls alert")):
        event["kind"] = "handshake_failure"
    else:
        return None
    return ip, event


def normalize_decoy_record(record: dict) -> tuple[str, dict] | None:
    """Recognize active scanner behaviour in a Caddy HTTP access record."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    ip = _remote_ip(request.get("remote_ip", request.get("remote_addr", "")))
    if ip is None:
        return None
    method = str(request.get("method", "GET")).upper()
    uri = str(request.get("uri", request.get("path", ""))).lower()
    suspicious = method in {"CONNECT", "TRACE", "TRACK"} or any(token in uri for token in (
        "/.env", "/wp-login", "/xmlrpc.php", "/actuator", "/cgi-bin/", "/server-status",
    ))
    if not suspicious:
        return None
    return ip, {"protocol": "https", "kind": "active_decoy_probe", "source": "caddy-decoy"}


def decayed_score(score: float, elapsed: float, half_life: float = SCORE_HALF_LIFE) -> float:
    """Decay evidence exponentially so old probes cannot cause a late ban."""
    if elapsed <= 0:
        return max(0.0, float(score))
    if half_life <= 0:
        return 0.0
    return max(0.0, float(score) * 0.5 ** (elapsed / half_life))


def score_event(event: dict) -> tuple[int, tuple[str, ...]]:
    """Return (score, signals) for a normalized L4 event.

    Supported fields are deliberately small: ``kind``/``reason``, ``sni``,
    ``protocol``, ``handshake_ok`` and ``connections_10s``.  Unknown fields
    are ignored so adapters can pass through their native log records.
    """
    if not isinstance(event, dict):
        return 0, ()
    signals: list[str] = []
    kind = str(event.get("kind", event.get("reason", ""))).lower()
    mapping = {
        "malformed_tls": ("malformed_tls",), "bad_client_hello": ("malformed_tls",),
        "non_tls": ("non_tls_on_tls",), "unknown_sni": ("unknown_sni",),
        "handshake_error": ("handshake_failure",), "handshake_failure": ("handshake_failure",),
        "protocol_mismatch": ("protocol_mismatch",), "invalid_first_packet": ("invalid_first_packet",),
        "active_decoy_probe": ("active_decoy_probe",), "auth_failure": ("auth_failure",),
        "port_scan": ("port_scan",),
    }
    signals.extend(mapping.get(kind, ()))
    protocol = str(event.get("protocol", "")).lower()
    if protocol in {"tls", "https", "quic"} and event.get("handshake_ok") is False:
        signals.append("handshake_failure")
    if event.get("sni_known") is False and "unknown_sni" not in signals:
        signals.append("unknown_sni")
    try:
        if int(event.get("distinct_ports_60s", 0)) >= 4:
            signals.append("port_sweep")
        if int(event.get("connections_10s", 0)) >= 12:
            signals.append("connection_burst")
        if protocol == "quic" and int(event.get("retries_10s", 0)) >= 6:
            signals.append("quic_retry_burst")
    except (TypeError, ValueError):
        pass
    unique = tuple(dict.fromkeys(signals))
    return sum(SIGNAL_WEIGHTS.get(signal, 0) for signal in unique), unique


def _run(command: list[str], *, text: bool = False, timeout: int = 20):
    try:
        return HOST.run(command, text=text, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, stdout="" if text else b"", stderr=str(exc))


def _scan_rule(binary: str, protocol: str) -> list[str]:
    """Build a rate-limited LOG-only rule; the scorer decides whether to ban."""
    version = "6" if binary == "ip6tables" else "4"
    if protocol == "tcp":
        transport = ["-p", "tcp", "--syn"]
        threshold, burst, prefix = "120/minute", "60", "HYDRA_SCAN_TCP "
    elif protocol == "udp":
        transport = ["-p", "udp"]
        threshold, burst, prefix = "300/minute", "150", "HYDRA_SCAN_UDP "
    else:
        raise ValueError(f"unsupported scan telemetry protocol: {protocol}")
    return [
        *transport,
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "hashlimit", "--hashlimit-above", threshold,
        "--hashlimit-burst", burst, "--hashlimit-mode", "srcip",
        "--hashlimit-name", f"hydra_adpi_{protocol}{version}",
        "-m", "limit", "--limit", "30/minute", "--limit-burst", "20",
        "-m", "comment", "--comment", SCAN_RULE_COMMENT,
        "-j", "LOG", "--log-prefix", prefix, "--log-level", "4",
    ]


class AntiDPIPlugin(BasePlugin):
    last_error = ""
    meta = PluginMeta(
        name="antidpi",
        description="Анти-DPI: поведенческое обнаружение зондов на всех протоколах и Caddy L4",
        category=PluginCategory.SECURITY,
        version="1.0.0",
        central_apply=False,
        required_commands=("ipset", "iptables", "ip6tables", "systemctl"),
    )

    def install(self) -> bool:
        self.last_error = ""
        missing = [name for name in self.meta.required_commands if HOST.which(name) is None]
        if missing:
            self._install_host_dependencies(missing)
            missing = [name for name in self.meta.required_commands if HOST.which(name) is None]
        if missing:
            return self._fail("Не найдены команды: " + ", ".join(missing))
        if not self._ensure_sets() or not self._ensure_rules() or not self._ensure_scan_rules():
            return False
        if not self._restore_bans():
            return False
        self._sync_awg_debug(True)
        try:
            self._write_service()
        except OSError as exc:
            return self._fail(f"Не удалось записать systemd unit: {exc}")
        reload_result = _run(["systemctl", "daemon-reload"], text=True)
        if reload_result.returncode != 0:
            return self._fail(self._result_error(reload_result, "systemctl daemon-reload"))
        start_result = _run(["systemctl", "enable", "--now", "hydra-antidpi"], text=True)
        if start_result.returncode != 0:
            return self._fail(self._result_error(start_result, "запуск hydra-antidpi"))
        if not self.status().running:
            return self._fail("hydra-antidpi не перешёл в active; проверьте journalctl -u hydra-antidpi")
        return True

    def _install_host_dependencies(self, missing: list[str]) -> None:
        packages: list[str] = []
        if any(name in missing for name in ("ipset", "iptables", "ip6tables")):
            packages.extend(("ipset", "iptables"))
        if not packages:
            return
        managers = (
            (["apt-get", "install", "-y", "-qq", *packages], 180),
            (["dnf", "install", "-y", "-q", *packages], 180),
            (["yum", "install", "-y", "-q", *packages], 180),
            (["apk", "add", "--no-cache", *packages], 180),
            (["pacman", "-S", "--noconfirm", *packages], 180),
        )
        for command, timeout in managers:
            if HOST.which(command[0]) is None:
                continue
            result = _run(command, text=True, timeout=timeout)
            if result.returncode == 0:
                return
            self.last_error = self._result_error(result, "установка firewall dependencies")

    def _fail(self, detail: str) -> bool:
        self.last_error = str(detail).strip()[:800]
        return False

    @staticmethod
    def _result_error(result, action: str) -> str:
        detail = result.stderr or result.stdout or "неизвестная ошибка"
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        return f"{action}: {' '.join(str(detail).split())[:650]}"

    def uninstall(self) -> bool:
        _run(["systemctl", "disable", "--now", "hydra-antidpi"])
        self._sync_awg_debug(False)
        ok = self._remove_scan_rules()
        ok = self._remove_rules() and ok
        for name in (SET_V4, SET_V6):
            _run(["ipset", "flush", name]); _run(["ipset", "destroy", name])
        for path in (SCRIPT_FILE, SERVICE_FILE, STATE_FILE):
            path.unlink(missing_ok=True)
        return ok

    def _sync_awg_debug(self, enabled: bool) -> bool:
        control = next((path for path in AWG_DEBUG_PATHS if path.exists()), None)
        if control is None:
            if not enabled:
                _run(["systemctl", "disable", "--now", "hydra-awg-antidpi-debug.service"])
                AWG_DEBUG_SERVICE.unlink(missing_ok=True)
            return True
        functions = ("prepare_awg_message", "wg_receive_handshake_packet")
        flag = "+p" if enabled else "-p"
        try:
            control.write_text("\n".join(f"module amneziawg func {name} {flag}" for name in functions) + "\n", encoding="utf-8")
        except OSError:
            return not enabled
        if not enabled:
            _run(["systemctl", "disable", "--now", "hydra-awg-antidpi-debug.service"])
            AWG_DEBUG_SERVICE.unlink(missing_ok=True)
            _run(["systemctl", "daemon-reload"])
            return True
        commands = "; ".join(f"echo 'module amneziawg func {name} +p'" for name in functions)
        stop = "; ".join(f"echo 'module amneziawg func {name} -p'" for name in functions)
        _atomic = f"""[Unit]\nAfter=systemd-modules-load.service\n[Service]\nType=oneshot\nExecStart=/bin/sh -c \"({commands}) > {control}\"\nExecStop=/bin/sh -c \"({stop}) > {control}\"\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n"""
        AWG_DEBUG_SERVICE.write_text(_atomic, encoding="utf-8")
        _run(["systemctl", "daemon-reload"])
        return _run(["systemctl", "enable", "--now", "hydra-awg-antidpi-debug.service"]).returncode == 0

    def _restore_bans(self) -> bool:
        now = time.time()
        with _lock_state_file():
            data = self._load_state()
            banned = data.get("banned", {})
            if not isinstance(banned, dict):
                return False
            ok = True
            for raw, metadata in list(banned.items()):
                try:
                    address = ipaddress.ip_address(raw)
                    banned_at = float((metadata or {}).get("at", 0))
                    duration = int((metadata or {}).get("duration", 86400))
                except (ValueError, TypeError):
                    banned.pop(raw, None)
                    continue
                remaining = int(duration - max(0, now - banned_at))
                if remaining <= 0:
                    banned.pop(raw, None)
                    continue
                set_name = SET_V6 if address.version == 6 else SET_V4
                ok = _run(["ipset", "add", set_name, address.compressed, "timeout", str(remaining), "-exist"]).returncode == 0 and ok
            data["banned"] = banned
            self._save_state(data)
            return ok

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def status(self) -> PluginStatus:
        active = _run(["systemctl", "is-active", "hydra-antidpi"], text=True)
        running = active.returncode == 0 and str(active.stdout).strip() == "active"
        data = self._load_state()
        return PluginStatus(installed=SCRIPT_FILE.exists() or SERVICE_FILE.exists(), enabled=running, running=running, info={"banned_ips": len(active_bans(data)), "events": data.get("events", 0), "last_error": self.last_error})

    def healthcheck(self) -> HealthResult:
        status = self.status()
        sets_ok = all(_run(["ipset", "list", name]).returncode == 0 for name in (SET_V4, SET_V6))
        rules_ok = True
        telemetry_ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            check = [binary, "-C", "INPUT", "-m", "set", "--match-set", name, "src", "-m", "comment", "--comment", RULE_COMMENT, "-j", "DROP"]
            rules_ok = _run(check).returncode == 0 and rules_ok
            for protocol in ("tcp", "udp"):
                telemetry_ok = _run([binary, "-C", "INPUT", *_scan_rule(binary, protocol)]).returncode == 0 and telemetry_ok
        checks = {"service": status.running, "ipsets": sets_ok, "firewall": rules_ok, "scan_telemetry": telemetry_ok}
        healthy = all(checks.values())
        return HealthResult(healthy, "" if healthy else "anti-DPI runtime is incomplete", "ok" if healthy else "error", checks)

    def on_enable(self, state: AppState) -> None:
        if not self.install():
            raise RuntimeError("Anti-DPI service or firewall could not be installed")

    def on_disable(self, state: AppState) -> None:
        if _run(["systemctl", "disable", "--now", "hydra-antidpi"]).returncode != 0:
            raise RuntimeError("Anti-DPI service could not be stopped")
        self._sync_awg_debug(False)
        if not self._remove_scan_rules():
            raise RuntimeError("Anti-DPI scan telemetry rules could not be removed")

    def observe_event(self, ip: str, event: dict, *, now: float | None = None) -> bool:
        """Record one normalized event; return True when the address is banned.

        Protocol plugins can call this without depending on Fail2ban or its
        log parser.  State updates are atomic enough for the single detector
        worker and are protected by IP validation before touching ipset.
        """
        try:
            parsed_address = ipaddress.ip_address(str(ip).strip("[]"))
            address = parsed_address.compressed
        except ValueError:
            return False
        event = dict(event) if isinstance(event, dict) else {}

        with _lock_state_file():
            data = self._load_state()
            if self._is_whitelisted(parsed_address, data):
                return False
            scores = data.setdefault("scores", {})
            entry = scores.setdefault(address, {"score": 0, "signals": [], "updated": 0, "last_unknown_sni_at": 0})
            timestamp = now if now is not None else time.time()

            source = str(event.get("source", "unknown"))[:80]
            if source == "kernel-firewall":
                try:
                    destination_port = int(event.get("destination_port", 0))
                except (TypeError, ValueError):
                    destination_port = 0
                recent_ports = entry.get("kernel_ports", {})
                if not isinstance(recent_ports, dict):
                    recent_ports = {}
                recent_ports = {
                    str(port): seen_at
                    for port, seen_at in recent_ports.items()
                    if isinstance(seen_at, (int, float)) and timestamp - float(seen_at) <= 60
                }
                if 1 <= destination_port <= 65535:
                    recent_ports[str(destination_port)] = timestamp
                entry["kernel_ports"] = dict(list(recent_ports.items())[-64:])
                event["distinct_ports_60s"] = len(recent_ports)

            score, signals = score_event(event)
            if source != "kernel-firewall" and signals:
                entry["last_non_kernel_evidence_at"] = timestamp
            if "port_sweep" in signals:
                entry["last_port_sweep_at"] = timestamp

            previous = float(entry.get("score", 0))
            previous_at = float(entry.get("updated", timestamp) or timestamp)

            # Consolidate parallel browser sockets for single page load (sub-0.5s window on pure unknown_sni)
            last_unknown_sni = float(entry.get("last_unknown_sni_at", 0) or 0)
            if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
                if timestamp - last_unknown_sni < 0.5:
                    score = 0.0
                else:
                    entry["last_unknown_sni_at"] = timestamp

            entry["score"] = round(decayed_score(previous, timestamp - previous_at) + score, 4)
            entry["signals"] = list(dict.fromkeys(list(entry.get("signals", [])) + list(signals)))[-16:]
            entry["updated"] = timestamp
            data["events"] = int(data.get("events", 0)) + 1
            source_counts = data.setdefault("source_counts", {})
            if not isinstance(source_counts, dict):
                source_counts = {}
                data["source_counts"] = source_counts
            source_counts[source] = int(source_counts.get(source, 0)) + 1
            signal_counts = data.setdefault("signal_counts", {})
            if not isinstance(signal_counts, dict):
                signal_counts = {}
                data["signal_counts"] = signal_counts
            for signal in signals:
                signal_counts[signal] = int(signal_counts.get(signal, 0)) + 1
            data["last_event_at"] = timestamp
            data["last_event_source"] = source
            if len(scores) > MAX_SCORE_ENTRIES or data["events"] % 256 == 0:
                prune_runtime_state(data, now=timestamp)

            banned_map = data.setdefault("banned", {})
            if not isinstance(banned_map, dict):
                banned_map = {}
                data["banned"] = banned_map
            active_metadata = banned_map.get(address)
            active_ban = False
            if isinstance(active_metadata, dict):
                try:
                    active_ban = timestamp < float(active_metadata.get("at", 0)) + int(active_metadata.get("duration", 0))
                except (TypeError, ValueError):
                    active_ban = False
                if not active_ban:
                    banned_map.pop(address, None)
                    for item in reversed(data.get("history", [])):
                        if isinstance(item, dict) and item.get("ip") == address and item.get("status") == "active":
                            item["status"] = "expired"
                            item["expired_at"] = timestamp
                            break

            last_non_kernel = float(entry.get("last_non_kernel_evidence_at", 0) or 0)
            last_port_sweep = float(entry.get("last_port_sweep_at", 0) or 0)
            ban_eligible = (
                (last_non_kernel > 0 and timestamp - last_non_kernel <= SCORE_HALF_LIFE * 2)
                or (last_port_sweep > 0 and timestamp - last_port_sweep <= SCORE_HALF_LIFE * 2)
            )
            last_alert_at = float(entry.get("last_alert_at", 0) or 0)
            should_alert = (
                not active_ban
                and signals
                and entry["score"] >= 6.0
                and not (entry["score"] >= BAN_THRESHOLD and ban_eligible)
                and timestamp - last_alert_at >= ALERT_COOLDOWN
            )
            if should_alert:
                entry["last_alert_at"] = timestamp
                try:
                    from hydra.services.telegram.bot import send_admin_notification
                    kind = html.escape(str(event.get("kind", event.get("reason", "anomaly"))))
                    proto = html.escape(str(event.get("protocol", "L4")))
                    sig_str = html.escape(", ".join(signals))
                    send_admin_notification(
                        f"🛡️ <b>AntiDPI Alert</b>\n"
                        f"<b>IP:</b> <code>{address}</code>\n"
                        f"<b>Protocol:</b> <code>{proto}</code> ({kind})\n"
                        f"<b>Signals:</b> <code>{sig_str}</code>\n"
                        f"<b>Score:</b> <code>{entry['score']:.1f} / {BAN_THRESHOLD}</code>",
                        category="antidpi",
                    )
                except Exception:
                    pass

            banned = active_ban or (entry["score"] >= BAN_THRESHOLD and ban_eligible)
            if banned:
                if active_ban:
                    self._save_state(data)
                    return True
                ban_counts = data.setdefault("ban_counts", {})
                offense_count = int(ban_counts.get(address, 0)) + 1
                duration = get_ban_duration(offense_count)

                set_name = SET_V6 if parsed_address.version == 6 else SET_V4
                if _run(["ipset", "add", set_name, address, "timeout", str(duration), "-exist"]).returncode == 0:
                    ban_counts[address] = offense_count
                    metadata = {
                        "at": entry["updated"],
                        "score": entry["score"],
                        "signals": entry["signals"],
                        "duration": duration,
                        "offense_count": offense_count,
                    }
                    banned_map[address] = metadata
                    history = data.setdefault("history", [])
                    if not isinstance(history, list):
                        history = []
                    history.append({"ip": address, **metadata, "status": "active"})
                    data["history"] = history[-1000:]
                    try:
                        from hydra.services.telegram.bot import send_admin_notification
                        sig_str = html.escape(", ".join(str(value) for value in entry["signals"]))
                        dur_str = f"{duration // 60}m" if duration < 3600 else (f"{duration // 3600}h" if duration < 86400 else f"{duration // 86400}d")
                        send_admin_notification(
                            f"🚨 <b>AntiDPI BAN</b>\n"
                            f"<b>IP:</b> <code>{address}</code>\n"
                            f"<b>Score:</b> <code>{entry['score']:.1f} / {BAN_THRESHOLD}</code>\n"
                            f"<b>Signals:</b> <code>{sig_str}</code>\n"
                            f"<b>Duration:</b> <code>{dur_str} (Offense #{offense_count})</code>",
                            category="antidpi",
                    )
                    except Exception:
                        pass
                else:
                    banned = False
            self._save_state(data)
            return banned

    def unban(self, raw: str) -> bool:
        """Remove an address from ipset and persistent evidence."""
        try:
            address = ipaddress.ip_address(str(raw).strip("[]"))
        except ValueError:
            return False
        name = SET_V6 if address.version == 6 else SET_V4
        result = _run(["ipset", "del", name, address.compressed], text=True)
        detail = str(result.stderr or result.stdout or "").lower()
        if result.returncode != 0 and "not in set" not in detail:
            return False
        with _lock_state_file():
            data = self._load_state()
            data.get("banned", {}).pop(address.compressed, None)
            data.get("scores", {}).pop(address.compressed, None)
            for item in reversed(data.get("history", [])):
                if isinstance(item, dict) and item.get("ip") == address.compressed and item.get("status") == "active":
                    item["status"] = "unbanned"
                    item["unbanned_at"] = time.time()
                    break
            self._save_state(data)
        return True

    @staticmethod
    def _is_whitelisted(address: ipaddress.IPv4Address | ipaddress.IPv6Address, data: dict) -> bool:
        if address.is_loopback or address.is_link_local:
            return True
        try:
            from hydra.core.state import load_state
            server_ip = load_state().network.server_ip
            if server_ip and address == ipaddress.ip_address(server_ip):
                return True
        except Exception:
            pass
        networks = list(DEFAULT_TRUSTED_NETWORKS) + _get_whitelisted_networks(data.get("whitelist", []))
        for net in networks:
            if address in net:
                return True
        return False

    def _load_state(self) -> dict:
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {"banned": {}, "scores": {}, "events": 0, "whitelist": [], "history": [], "ban_counts": {}}

    def _save_state(self, data: dict) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = STATE_FILE.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(STATE_FILE)

    def _ensure_sets(self) -> bool:
        ok = True
        for name, family in ((SET_V4, "inet"), (SET_V6, "inet6")):
            result = _run(["ipset", "create", name, "hash:ip", "family", family, "timeout", "86400", "-exist"], text=True)
            if result.returncode != 0:
                ok = self._fail(self._result_error(result, f"создание ipset {name}")) and ok
        return ok

    def _ensure_rules(self) -> bool:
        ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            rule = [binary, "-C", "INPUT", "-m", "set", "--match-set", name, "src", "-m", "comment", "--comment", RULE_COMMENT, "-j", "DROP"]
            if _run(rule).returncode != 0:
                add = _run([binary, "-I", "INPUT", "1", *rule[3:]], text=True)
                if add.returncode != 0:
                    self._fail(self._result_error(add, f"правило {binary} для {name}"))
                    ok = False
        return ok

    def _remove_rules(self) -> bool:
        ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            check = [binary, "-C", "INPUT", "-m", "set", "--match-set", name, "src", "-m", "comment", "--comment", RULE_COMMENT, "-j", "DROP"]
            for _ in range(32):
                if _run(check).returncode != 0:
                    break
                if _run([binary, "-D", *check[2:]]).returncode != 0:
                    ok = False
                    break
        return ok

    def _ensure_scan_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for protocol in ("tcp", "udp"):
                spec = _scan_rule(binary, protocol)
                if _run([binary, "-C", "INPUT", *spec]).returncode == 0:
                    continue
                result = _run([binary, "-I", "INPUT", "2", *spec], text=True)
                if result.returncode != 0:
                    self._fail(self._result_error(result, f"scan telemetry {binary}/{protocol}"))
                    ok = False
        return ok

    def _remove_scan_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for protocol in ("tcp", "udp"):
                spec = _scan_rule(binary, protocol)
                check = [binary, "-C", "INPUT", *spec]
                for _ in range(32):
                    if _run(check).returncode != 0:
                        break
                    if _run([binary, "-D", "INPUT", *spec]).returncode != 0:
                        ok = False
                        break
        return ok

    def _write_service(self) -> None:
        SCRIPT_FILE.parent.mkdir(parents=True, exist_ok=True)
        wrapper = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.path.insert(0, {str(PROJECT_ROOT)!r})\n"
            "from hydra.plugins.antidpi.agent import run\n"
            "run()\n"
        )
        SCRIPT_FILE.write_text(wrapper, encoding="utf-8")
        SCRIPT_FILE.chmod(0o755)
        SERVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SERVICE_FILE.write_text(f"""[Unit]
Description=HYDRA Anti-DPI probe detector
After=network-online.target caddy-l4.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory={PROJECT_ROOT}
ExecStart={sys.executable} {SCRIPT_FILE}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/hydra /var/log/caddy-l4
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
""", encoding="utf-8")


# Compatibility spelling for callers that derive plugin names mechanically.
AntidpiPlugin = AntiDPIPlugin
