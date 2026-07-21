"""Behavioural anti-DPI detector, deliberately independent from Fail2ban.

The detector consumes structured events from Caddy L4 (or any protocol
adapter), scores several weak signals, and bans only after a configurable
combination is observed.  It is intentionally conservative: a single
malformed packet never causes a ban.
"""
# audit: allow-generated-runtime-subprocess
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state import AppState, load_state
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
UDP_PROBE_RULE_COMMENT = "hydra-antidpi-udp-probes"
UDP_PROBE_CHAIN = "HYDRA_ANTIDPI_UDP"
MIERU_PROBE_RULE_COMMENT = "hydra-antidpi-mieru-probes"
MIERU_PORT_RANGE = "2012:2022"
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Signals are protocol-independent.  A score is more robust than a single
# regex and keeps normal clients from being banned on one transient failure.
SIGNAL_WEIGHTS = {
    "malformed_tls": 4, "non_tls_on_tls": 3, "unknown_sni": 2,
    "handshake_failure": 2, "protocol_mismatch": 3, "quic_retry_burst": 2,
    "connection_burst": 2, "invalid_first_packet": 3,
    "active_decoy_probe": 8, "auth_failure": 3, "port_scan": 2,
    "port_sweep": 6,
    "udp_probe": 4,
    "low_volume_session": 3,
}

SCORE_HALF_LIFE = 300.0
BAN_THRESHOLD = 8
ALERT_THRESHOLD = 6
AUTH_ALERT_THRESHOLD = 3
BAN_DURATIONS = (600, 3600, 86400, 604800)  # 10m -> 1h -> 24h -> 7d
LEGACY_BAN_DURATION = 86400
ALERT_COOLDOWN = 300.0
MAX_OBSERVED_SCORE = BAN_THRESHOLD * 2
BAN_NOTIFICATION_COOLDOWN = 5.0
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


def format_score(value: object) -> str:
    """Render detector precision without visually crossing the ban threshold."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = 0.0
    return f"{score:.2f}/{BAN_THRESHOLD:.2f}"


def _track_notification(data: dict, delivered: bool, *, now: float) -> None:
    """Persist delivery telemetry without storing Telegram credentials."""
    stats = data.setdefault("notification_stats", {})
    if not isinstance(stats, dict):
        stats = {}
        data["notification_stats"] = stats
    stats["attempted"] = int(stats.get("attempted", 0)) + 1
    stats["last_attempt_at"] = now
    key = "delivered" if delivered else "failed"
    stats[key] = int(stats.get(key, 0)) + 1
    stats[f"last_{key}_at"] = now


def ban_duration(metadata: object) -> int:
    """Return persisted duration, preserving the old 24-hour ban format."""
    if not isinstance(metadata, dict):
        return 0
    try:
        return max(0, int(metadata.get("duration", LEGACY_BAN_DURATION)))
    except (TypeError, ValueError):
        return 0


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
            expires_at = float(metadata.get("at", 0)) + ban_duration(metadata)
        except (TypeError, ValueError):
            continue
        if timestamp < expires_at:
            result[address] = metadata
    return result


def expire_bans(data: dict, *, now: float | None = None) -> bool:
    """Remove elapsed bans and reconcile their latest history records."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        data["banned"] = {}
        return True
    timestamp = time.time() if now is None else now
    expired: set[str] = set()
    changed = False
    for address, metadata in list(banned.items()):
        if not isinstance(metadata, dict):
            banned.pop(address, None)
            changed = True
            continue
        try:
            elapsed = timestamp >= float(metadata.get("at", 0)) + ban_duration(metadata)
        except (TypeError, ValueError):
            elapsed = True
        if elapsed:
            banned.pop(address, None)
            expired.add(address)
            changed = True
    if not expired:
        return changed
    remaining = set(expired)
    history = data.get("history", [])
    if isinstance(history, list):
        for item in reversed(history):
            if not isinstance(item, dict):
                continue
            address = item.get("ip")
            if address in remaining and item.get("status") == "active":
                item["status"] = "expired"
                item["expired_at"] = timestamp
                remaining.remove(address)
                if not remaining:
                    break
    return changed



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


def normalize_naive_decoy_record(record: dict) -> tuple[str, dict] | None:
    """Recognize scanner paths without treating valid Naive CONNECT as probes."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    ip = _remote_ip(request.get("remote_ip", request.get("remote_addr", "")))
    try:
        status = int(record.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    method = str(request.get("method", "GET")).upper()
    user_id = str(request.get("user_id", record.get("user_id", ""))).lower()
    def auth_event() -> tuple[str, dict] | None:
        if ip is None:
            return None
        event = {"protocol": "naive", "kind": "auth_failure", "source": "caddy-naive"}
        if ipaddress.ip_address(ip).is_loopback:
            try:
                peer_port = int(request.get("remote_port", 0))
            except (TypeError, ValueError):
                peer_port = 0
            if peer_port > 0:
                event["peer_port"] = peer_port
        return ip, event
    if user_id.startswith("invalid:") and ip is not None:
        return auth_event()
    if method == "CONNECT":
        if status in {401, 407} and ip is not None:
            return auth_event()
        return None
    normalized = normalize_decoy_record(record)
    if normalized is not None:
        address, event = normalized
        event["source"] = "caddy-naive-decoy"
        return address, event
    if status in {401, 407} and ip is not None:
        return auth_event()
    return None


def normalize_trusttunnel_record(record: dict) -> tuple[str, dict] | None:
    """Recognize completed TrustTunnel auth failures in its dedicated log."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    ip = _remote_ip(request.get("remote_ip", request.get("client_ip", "")))
    if ip is None:
        return None
    method = str(request.get("method", "")).upper()
    try:
        status = int(record.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    if method == "CONNECT" and status >= 400:
        return ip, {
            "protocol": "trusttunnel", "kind": "auth_failure",
            "source": "caddy-trusttunnel",
        }
    normalized = normalize_decoy_record(record)
    if normalized is not None:
        address, event = normalized
        event["source"] = "caddy-trusttunnel-decoy"
        return address, event
    return None


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
        "port_scan": ("port_scan",), "udp_probe": ("udp_probe",),
        "low_volume_session": ("low_volume_session",),
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


def udp_protocol_ports(state: AppState) -> dict[int, str]:
    """Return enabled public UDP listeners relevant to protocol probing."""
    result: dict[int, str] = {}

    def add(raw_port: object, owner: str) -> None:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return
        if 1 <= port <= 65535:
            current = result.get(port)
            owners = set(current.split("/")) if current else set()
            owners.add(owner)
            result[port] = "/".join(sorted(owners))

    for name in ("hysteria2", "amneziawg", "wdtt", "naive", "trusttunnel"):
        protocol = state.protocols.get(name)
        if not protocol or not protocol.enabled:
            continue
        config = protocol.config if isinstance(protocol.config, dict) else {}
        if name == "amneziawg":
            profiles = config.get("profiles", {})
            if isinstance(profiles, dict):
                for profile in profiles.values():
                    if isinstance(profile, dict) and profile.get("port"):
                        add(profile["port"], name)
            if not any(name in value.split("/") for value in result.values()):
                add(protocol.port or 51820, name)
        elif name == "hysteria2":
            add(config.get("port", protocol.port or 8443), name)
        elif name == "wdtt":
            add(config.get("dtls_port", 56000), name)
        elif name == "naive" and str(config.get("network", "tcp")) in {"quic", "both"}:
            add(443, name)
        elif name == "trusttunnel" and str(config.get("transport", "tcp")) in {"quic", "both"}:
            add(443, name)
    return {port: result[port] for port in sorted(result)}


def _udp_probe_rule(binary: str, port: int) -> list[str]:
    version = "6" if binary == "ip6tables" else "4"
    return [
        "-p", "udp", "--dport", str(int(port)),
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "hashlimit", "--hashlimit-above", "12/minute",
        "--hashlimit-burst", "4", "--hashlimit-mode", "srcip",
        "--hashlimit-name", f"hadp{version}_{int(port)}",
        "-m", "limit", "--limit", "30/minute", "--limit-burst", "10",
        "-j", "LOG", "--log-prefix", "HYDRA_UDP_PROBE ", "--log-level", "4",
    ]


def _mieru_probe_rule(binary: str, close_flag: str) -> list[str]:
    """Log repeated established Mieru sessions that close after <=1 KiB client traffic."""
    version = "6" if binary == "ip6tables" else "4"
    flag = str(close_flag).upper()
    return [
        "-p", "tcp", "--dport", MIERU_PORT_RANGE,
        "--tcp-flags", "FIN,RST", flag,
        "-m", "conntrack", "--ctstate", "ESTABLISHED",
        "-m", "connbytes", "--connbytes", "1:1024",
        "--connbytes-dir", "original", "--connbytes-mode", "bytes",
        "-m", "hashlimit", "--hashlimit-above", "2/minute",
        "--hashlimit-burst", "2", "--hashlimit-mode", "srcip",
        "--hashlimit-name", f"hadp_mieru_{flag.lower()}{version}",
        "-m", "limit", "--limit", "30/minute", "--limit-burst", "10",
        "-m", "comment", "--comment", MIERU_PROBE_RULE_COMMENT,
        "-j", "LOG", "--log-prefix", "HYDRA_MIERU_SHORT ", "--log-level", "4",
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
        if (
            not self._ensure_sets() or not self._ensure_rules()
            or not self._ensure_scan_rules() or not self.sync_udp_probe_rules()
            or not self.sync_mieru_probe_rules()
        ):
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
        enable_result = _run(["systemctl", "enable", "hydra-antidpi"], text=True)
        if enable_result.returncode != 0:
            return self._fail(self._result_error(enable_result, "enable hydra-antidpi"))
        # install() is also the supported update/sync operation. An already
        # active unit must be restarted to load the new collector code and
        # the freshly generated systemd sandbox.
        start_result = _run(["systemctl", "restart", "hydra-antidpi"], text=True)
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
        ok = self._remove_udp_probe_rules()
        ok = self._remove_mieru_probe_rules() and ok
        ok = self._remove_scan_rules() and ok
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
        functions = (
            "prepare_awg_message",
            "wg_receive_handshake_packet",
            "wg_noise_handshake_consume_initiation",
        )
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
                    duration = ban_duration(metadata)
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
        udp_probe_ok = True
        mieru_probe_ok = True
        try:
            state = load_state()
            mieru_enabled = bool(state.protocols.get("mieru") and state.protocols["mieru"].enabled)
        except Exception:
            mieru_enabled = False
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            check = [binary, "-C", "INPUT", "-m", "set", "--match-set", name, "src", "-m", "comment", "--comment", RULE_COMMENT, "-j", "DROP"]
            rules_ok = _run(check).returncode == 0 and rules_ok
            for protocol in ("tcp", "udp"):
                telemetry_ok = _run([binary, "-C", "INPUT", *_scan_rule(binary, protocol)]).returncode == 0 and telemetry_ok
            jump = [
                "-p", "udp", "-m", "comment", "--comment", UDP_PROBE_RULE_COMMENT,
                "-j", UDP_PROBE_CHAIN,
            ]
            udp_probe_ok = _run([binary, "-C", "INPUT", *jump]).returncode == 0 and udp_probe_ok
            if mieru_enabled:
                for flag in ("FIN", "RST"):
                    mieru_probe_ok = (
                        _run([binary, "-C", "INPUT", *_mieru_probe_rule(binary, flag)]).returncode == 0
                        and mieru_probe_ok
                    )
        checks = {
            "service": status.running, "ipsets": sets_ok, "firewall": rules_ok,
            "scan_telemetry": telemetry_ok, "udp_probe_telemetry": udp_probe_ok,
            "mieru_probe_telemetry": mieru_probe_ok,
        }
        healthy = all(checks.values())
        return HealthResult(healthy, "" if healthy else "anti-DPI runtime is incomplete", "ok" if healthy else "error", checks)

    def on_enable(self, state: AppState) -> None:
        if not self.install():
            raise RuntimeError("Anti-DPI service or firewall could not be installed")

    def on_disable(self, state: AppState) -> None:
        if _run(["systemctl", "disable", "--now", "hydra-antidpi"]).returncode != 0:
            raise RuntimeError("Anti-DPI service could not be stopped")
        self._sync_awg_debug(False)
        if (
            not self._remove_scan_rules() or not self._remove_udp_probe_rules()
            or not self._remove_mieru_probe_rules()
        ):
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
            evidence_can_ban = event.get("ban_eligible") is not False
            if source not in {"kernel-firewall", "kernel-udp-probe"} and signals and evidence_can_ban:
                entry["last_non_kernel_evidence_at"] = timestamp
            if "port_sweep" in signals and evidence_can_ban:
                entry["last_port_sweep_at"] = timestamp

            previous = float(entry.get("score", 0))
            # Legacy state did not distinguish spoofable UDP evidence. Start
            # its verified accumulator at zero instead of trusting old score.
            previous_verified = float(entry.get("verified_score", 0))
            previous_at = float(entry.get("updated", timestamp) or timestamp)

            # Consolidate parallel browser sockets for single page load (sub-0.5s window on pure unknown_sni)
            last_unknown_sni = float(entry.get("last_unknown_sni_at", 0) or 0)
            if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
                if timestamp - last_unknown_sni < 0.5:
                    score = 0.0
                else:
                    entry["last_unknown_sni_at"] = timestamp

            entry["score"] = round(min(
                MAX_OBSERVED_SCORE,
                decayed_score(previous, timestamp - previous_at) + score,
            ), 4)
            entry["verified_score"] = round(
                decayed_score(previous_verified, timestamp - previous_at)
                + (score if evidence_can_ban else 0.0),
                4,
            )
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
            if data["events"] % 256 == 0:
                expire_bans(data, now=timestamp)
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
            ban_eligible = evidence_can_ban and (
                (last_non_kernel > 0 and timestamp - last_non_kernel <= SCORE_HALF_LIFE * 2)
                or (last_port_sweep > 0 and timestamp - last_port_sweep <= SCORE_HALF_LIFE * 2)
            )
            protocol_key = str(event.get("protocol", "L4"))[:40].lower()
            protocol_alerts = entry.get("protocol_alerts", {})
            if not isinstance(protocol_alerts, dict):
                protocol_alerts = {}
            protocol_alerts = {
                str(key): float(value)
                for key, value in protocol_alerts.items()
                if isinstance(value, (int, float)) and timestamp - float(value) <= ALERT_COOLDOWN * 4
            }
            last_alert_at = float(protocol_alerts.get(protocol_key, 0) or 0)
            should_alert = (
                not active_ban
                and signals
                and entry["score"] >= (
                    AUTH_ALERT_THRESHOLD if "auth_failure" in signals else ALERT_THRESHOLD
                )
                and not (entry["verified_score"] >= BAN_THRESHOLD and ban_eligible)
                and timestamp - last_alert_at >= ALERT_COOLDOWN
            )
            if should_alert:
                entry["last_alert_at"] = timestamp
                protocol_alerts[protocol_key] = timestamp
                entry["protocol_alerts"] = protocol_alerts
                delivered = False
                try:
                    from hydra.services.telegram.bot import format_security_event, send_admin_notification
                    from hydra.services.security_intel import notification_fields
                    kind = str(event.get("kind", event.get("reason", "anomaly")))
                    proto = str(event.get("protocol", "L4"))
                    fields = [
                            ("IP", address),
                            *notification_fields(address),
                            ("Event", kind),
                            ("Protocol", proto),
                            ("Source", source),
                            ("Signals", ", ".join(signals)),
                            ("Score", format_score(entry["score"])),
                    ]
                    if not evidence_can_ban:
                        fields.append(("Policy", str(
                            event.get("policy", "alert-only / unverified UDP source")
                        )))
                    if entry["verified_score"] != entry["score"]:
                        fields.append(("Verified score", format_score(entry["verified_score"])))
                    delivered = bool(send_admin_notification(
                        format_security_event("AntiDPI", "ALERT", fields),
                        category="antidpi",
                        reply_markup={
                            "inline_keyboard": [[{
                                "text": "🚫 Заблокировать",
                                "callback_data": f"antidpi-ban:{address}",
                            }]],
                        },
                    ))
                except Exception:
                    pass
                _track_notification(data, delivered, now=timestamp)

            banned = active_ban or (entry["verified_score"] >= BAN_THRESHOLD and ban_eligible)
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
                        "score": entry["verified_score"],
                        "signals": entry["signals"],
                        "source": source,
                        "protocol": str(event.get("protocol", "unknown"))[:40],
                        "kind": str(event.get("kind", event.get("reason", "anomaly")))[:80],
                        "duration": duration,
                        "offense_count": offense_count,
                    }
                    banned_map[address] = metadata
                    history = data.setdefault("history", [])
                    if not isinstance(history, list):
                        history = []
                    history.append({"ip": address, **metadata, "status": "active"})
                    data["history"] = history[-1000:]
                    last_notice = float(data.get("last_ban_notification_at", 0) or 0)
                    if timestamp - last_notice >= BAN_NOTIFICATION_COOLDOWN:
                        data["last_ban_notification_at"] = timestamp
                        delivered = False
                        try:
                            from hydra.services.telegram.bot import format_security_event, send_admin_notification
                            from hydra.services.security_intel import notification_fields
                            dur_str = f"{duration // 60}m" if duration < 3600 else (f"{duration // 3600}h" if duration < 86400 else f"{duration // 86400}d")
                            delivered = bool(send_admin_notification(
                                format_security_event("AntiDPI", "BAN", [
                                    ("IP", address),
                                    *notification_fields(address),
                                    ("Event", event.get("kind", "anomaly")),
                                    ("Protocol", event.get("protocol", "L4")),
                                    ("Source", source),
                                    ("Signals", ", ".join(str(value) for value in entry["signals"])),
                                    ("Score", format_score(entry["score"])),
                                    ("TTL", dur_str),
                                    ("Offense", offense_count),
                                ]),
                                category="antidpi",
                            ))
                        except Exception:
                            pass
                        _track_notification(data, delivered, now=timestamp)
                    else:
                        data["suppressed_ban_notifications"] = int(
                            data.get("suppressed_ban_notifications", 0)
                        ) + 1
                else:
                    banned = False
            self._save_state(data)
            return banned

    def cleanup_honeypot_duplicates(self) -> int:
        """Drop AntiDPI ownership for addresses already owned by Honeypot."""
        try:
            from hydra.plugins.honeypot.plugin import HoneypotPlugin
            honeypot_bans = set(HoneypotPlugin()._load_state().get("banned", {}))
        except Exception:
            return 0
        antidpi_bans = set(active_bans(self._load_state()))
        removed = 0
        for address in sorted(antidpi_bans & honeypot_bans):
            if self.unban(address):
                removed += 1
        return removed

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

    def manual_ban(self, raw: str, *, source: str = "manual") -> dict:
        """Block a validated address immediately on an explicit admin decision."""
        try:
            address = ipaddress.ip_address(str(raw).strip().strip("[]"))
        except ValueError:
            return {"ok": False, "error": "invalid_ip"}

        if not self._ensure_sets() or not self._ensure_rules():
            return {"ok": False, "error": "firewall_error"}

        timestamp = time.time()
        compressed = address.compressed
        with _lock_state_file():
            data = self._load_state()
            if self._is_whitelisted(address, data):
                return {"ok": False, "error": "whitelisted"}

            expire_bans(data, now=timestamp)
            current = active_bans(data, now=timestamp).get(compressed)
            if isinstance(current, dict):
                remaining = max(
                    0,
                    int(float(current.get("at", 0)) + ban_duration(current) - timestamp),
                )
                return {
                    "ok": True,
                    "already_active": True,
                    "remaining": remaining,
                    **current,
                }

            ban_counts = data.setdefault("ban_counts", {})
            if not isinstance(ban_counts, dict):
                ban_counts = {}
                data["ban_counts"] = ban_counts
            offense_count = int(ban_counts.get(compressed, 0) or 0) + 1
            duration = get_ban_duration(offense_count)
            set_name = SET_V6 if address.version == 6 else SET_V4
            result = _run(
                ["ipset", "add", set_name, compressed, "timeout", str(duration), "-exist"],
                text=True,
            )
            if result.returncode != 0:
                return {"ok": False, "error": "firewall_error"}

            scores = data.get("scores", {})
            if not isinstance(scores, dict):
                scores = {}
            entry = scores.get(compressed, {})
            if not isinstance(entry, dict):
                entry = {}
            signals = entry.get("signals", [])
            if not isinstance(signals, list):
                signals = [str(signals)] if signals else []
            signals = list(dict.fromkeys([*signals, "manual_ban"]))[-16:]
            metadata = {
                "at": timestamp,
                "score": float(entry.get("verified_score", entry.get("score", 0)) or 0),
                "signals": signals,
                "source": str(source)[:80],
                "protocol": "manual",
                "kind": "manual_ban",
                "duration": duration,
                "offense_count": offense_count,
            }
            banned = data.setdefault("banned", {})
            if not isinstance(banned, dict):
                banned = {}
                data["banned"] = banned
            banned[compressed] = metadata
            ban_counts[compressed] = offense_count
            history = data.setdefault("history", [])
            if not isinstance(history, list):
                history = []
            history.append({"ip": compressed, **metadata, "status": "active"})
            data["history"] = history[-1000:]
            self._save_state(data)
            return {"ok": True, "already_active": False, **metadata}

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

    def sync_udp_probe_rules(self, state: AppState | None = None) -> bool:
        """Refresh low-rate, LOG-only telemetry for enabled UDP protocols."""
        if state is None:
            try:
                from hydra.core.state import load_state
                state = load_state()
            except Exception:
                return False
        ports = udp_protocol_ports(state)
        ok = True
        for binary in ("iptables", "ip6tables"):
            _run([binary, "-N", UDP_PROBE_CHAIN])
            jump = [
                "-p", "udp", "-m", "comment", "--comment", UDP_PROBE_RULE_COMMENT,
                "-j", UDP_PROBE_CHAIN,
            ]
            if _run([binary, "-C", "INPUT", *jump]).returncode != 0:
                result = _run([binary, "-I", "INPUT", "2", *jump], text=True)
                if result.returncode != 0:
                    self._fail(self._result_error(result, f"UDP telemetry jump {binary}"))
                    ok = False
                    continue
            if _run([binary, "-F", UDP_PROBE_CHAIN], text=True).returncode != 0:
                ok = False
                continue
            for port in ports:
                result = _run([binary, "-A", UDP_PROBE_CHAIN, *_udp_probe_rule(binary, port)], text=True)
                if result.returncode != 0:
                    self._fail(self._result_error(result, f"UDP telemetry {binary}/{port}"))
                    ok = False
        return ok

    def _remove_udp_probe_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            jump = [
                "-p", "udp", "-m", "comment", "--comment", UDP_PROBE_RULE_COMMENT,
                "-j", UDP_PROBE_CHAIN,
            ]
            for _ in range(8):
                if _run([binary, "-C", "INPUT", *jump]).returncode != 0:
                    break
                ok = _run([binary, "-D", "INPUT", *jump]).returncode == 0 and ok
            _run([binary, "-F", UDP_PROBE_CHAIN])
            delete = _run([binary, "-X", UDP_PROBE_CHAIN])
            if delete.returncode != 0:
                detail = str(delete.stderr or delete.stdout or "").lower()
                if "no chain" not in detail and "does not exist" not in detail:
                    ok = False
        return ok

    def sync_mieru_probe_rules(self, state: AppState | None = None) -> bool:
        """Install LOG-only inference for Mieru's otherwise silent auth rejects."""
        if state is None:
            try:
                from hydra.core.state import load_state
                state = load_state()
            except Exception:
                return False
        protocol = state.protocols.get("mieru")
        enabled = bool(protocol and protocol.enabled)
        ok = self._remove_mieru_probe_rules()
        if not enabled:
            return ok
        for binary in ("iptables", "ip6tables"):
            for flag in ("FIN", "RST"):
                spec = _mieru_probe_rule(binary, flag)
                result = _run([binary, "-I", "INPUT", "2", *spec], text=True)
                if result.returncode != 0:
                    self._fail(self._result_error(result, f"Mieru telemetry {binary}/{flag}"))
                    ok = False
        return ok

    def _remove_mieru_probe_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for flag in ("FIN", "RST"):
                spec = _mieru_probe_rule(binary, flag)
                for _ in range(8):
                    if _run([binary, "-C", "INPUT", *spec]).returncode != 0:
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
# AF_INET/AF_INET6 are required for outbound Telegram HTTPS notifications.
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
""", encoding="utf-8")


# Compatibility spelling for callers that derive plugin names mechanically.
AntidpiPlugin = AntiDPIPlugin
