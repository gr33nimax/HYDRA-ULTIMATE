"""
hydra/plugins/dnscrypt/plugin.py — DNSCrypt-proxy.

Устанавливает и настраивает DNSCrypt-proxy на 127.0.0.1:5300.
Sing-Box использует его как upstream DNS-сервер.
"""
from __future__ import annotations

import base64
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.host import HOST

def get_dnscrypt_bin() -> Path:
    for p in ["/usr/sbin/dnscrypt-proxy", "/usr/bin/dnscrypt-proxy"]:
        path = Path(p)
        if path.exists():
            return path
    return Path("/usr/sbin/dnscrypt-proxy")

DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
DNSCRYPT_PORT = 5300
RESOLVER_CACHE_PATHS = (
    Path("/etc/dnscrypt-proxy/public-resolvers.md"),
    Path("/var/cache/dnscrypt-proxy/public-resolvers.md"),
    Path("/var/lib/dnscrypt-proxy/public-resolvers.md"),
    Path("/usr/local/etc/dnscrypt-proxy/public-resolvers.md"),
)


def _read_server_names() -> list[str]:
    if not DNSCRYPT_CONF.exists():
        return []
    try:
        content = DNSCRYPT_CONF.read_text(encoding="utf-8")
        match = re.search(
            r"^server_names\s*=\s*\[([^\]]+)\]",
            content,
            re.MULTILINE,
        )
        if not match:
            return []
        return [
            value.strip().strip("'\"")
            for value in match.group(1).split(",")
            if value.strip()
        ]
    except Exception:
        return []


def _decode_resolver_stamp(stamp: str) -> tuple[str, int] | None:
    try:
        padding = 4 - len(stamp) % 4
        if padding != 4:
            stamp += "=" * padding
        data = base64.urlsafe_b64decode(stamp)
        if len(data) < 10:
            return None
        address_length = data[9]
        if len(data) < 10 + address_length:
            return None
        raw = data[10:10 + address_length].decode(
            "utf-8",
            errors="replace",
        ).strip()
        if not raw:
            return None

        port = 443
        address = raw
        if raw.startswith("["):
            bracket_end = raw.find("]")
            if bracket_end != -1:
                address = raw[1:bracket_end]
                suffix = raw[bracket_end + 1:]
                if suffix.startswith(":"):
                    try:
                        port = int(suffix[1:])
                    except ValueError:
                        pass
        elif ":" in raw:
            address, candidate = raw.rsplit(":", 1)
            try:
                port = int(candidate)
            except ValueError:
                pass
        return (address, port) if address else None
    except Exception:
        return None


def _resolver_addresses() -> dict[str, tuple[str, list[int]]]:
    content = ""
    for path in RESOLVER_CACHE_PATHS:
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            break
        except Exception:
            pass
    if not content:
        return {}

    result: dict[str, tuple[str, list[int]]] = {}
    current_name: str | None = None
    stamps: list[tuple[str, int]] = []

    def flush() -> None:
        if not current_name or not stamps:
            return
        address = stamps[0][0]
        ports: list[int] = []
        for _, port in stamps:
            if port not in ports:
                ports.append(port)
        for fallback in (443, 853, 5353, 8443, 9953):
            if fallback not in ports:
                ports.append(fallback)
        result[current_name] = (address, ports[:5])

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            flush()
            current_name = line[3:].strip()
            stamps = []
        elif line.startswith("sdns://") and current_name:
            decoded = _decode_resolver_stamp(line[7:])
            if decoded:
                stamps.append(decoded)
    flush()
    return result


def _measure_resolver_latency(
    resolvers: list[str],
) -> list[tuple[str, float]]:
    addresses = _resolver_addresses()

    def probe(name: str) -> tuple[str, float]:
        entry = addresses.get(name)
        if not entry:
            return name, 9999.0
        address, ports = entry
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        for port in ports:
            try:
                started = time.monotonic()
                with socket.socket(family, socket.SOCK_STREAM) as stream:
                    stream.settimeout(2.0)
                    stream.connect((address, port))
                return name, round((time.monotonic() - started) * 1000, 1)
            except Exception:
                continue
        return name, 9999.0

    measured: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(probe, name) for name in resolvers]
        for future in as_completed(futures):
            measured.append(future.result())
    reachable = sorted(
        (item for item in measured if item[1] < 9999.0),
        key=lambda item: item[1],
    )
    reachable_names = {name for name, _ in reachable}
    return reachable + [
        (name, 9999.0)
        for name in resolvers
        if name not in reachable_names
    ]


class DNSCryptPlugin(BasePlugin):
    meta = PluginMeta(
        name="dnscrypt",
        description="DNSCrypt-proxy: шифрование DNS (DoH/DNSCrypt) на системном уровне",
        category=PluginCategory.ENHANCEMENT,
        version="2.0.0",
        required_commands=("systemctl",),
        queries=(
            "current_server_names",
            "measure_resolvers",
            "resolution_probe",
            "resolver_catalog",
        ),
        actions=("apply_server_names",),
        backup_resources=(
            BackupResource("/etc/dnscrypt-proxy", "tree"),
        ),
    )

    @staticmethod
    def current_server_names() -> list[str]:
        """Return configured resolver names without exposing config paths."""
        return _read_server_names()

    @staticmethod
    def resolver_catalog() -> tuple[list[str], bool, str]:
        """Return cached resolver names plus bounded diagnostic details."""
        details = [
            f"Cache file {path}: exists={path.exists()}"
            for path in RESOLVER_CACHE_PATHS
        ]
        try:
            names = list(_resolver_addresses())
            details.append(
                f"Loaded {len(names)} resolvers directly from public-resolvers.md",
            )
            if names:
                return names, False, "\n".join(details)
        except Exception as exc:
            details.append(f"Error parsing public-resolvers.md: {exc}")
        details.append("public-resolvers.md cache is empty or not found")
        return [], False, "\n".join(details)

    @staticmethod
    def measure_resolvers(
        *,
        resolvers: list[str],
    ) -> list[tuple[str, float]]:
        """Measure resolver reachability behind the plugin boundary."""
        return _measure_resolver_latency(resolvers)

    @staticmethod
    def apply_server_names(*, names: list[str]) -> bool:
        """Atomically validate and activate a resolver selection."""
        if (
            not DNSCRYPT_CONF.exists()
            or not names
            or any(
                not re.fullmatch(r"[A-Za-z0-9._-]+", name)
                for name in names
            )
        ):
            return False
        previous = DNSCRYPT_CONF.read_bytes()
        try:
            content = DNSCRYPT_CONF.read_text(encoding="utf-8")
            names_value = ", ".join(f"'{name}'" for name in names)
            replacement = f"server_names = [{names_value}]"
            if re.search(r"^server_names\s*=", content, re.MULTILINE):
                content = re.sub(
                    r"^server_names\s*=\s*\[.*?\]",
                    replacement,
                    content,
                    count=1,
                    flags=re.MULTILINE | re.DOTALL,
                )
            else:
                updated = re.sub(
                    r"(^listen_addresses\s*=\s*\[.*?\]\n)",
                    rf"\1{replacement}\n",
                    content,
                    count=1,
                    flags=re.MULTILINE,
                )
                content = (
                    updated
                    if updated != content
                    else f"{replacement}\n{content}"
                )
            HOST.atomic_write(DNSCRYPT_CONF, content)
            checked = HOST.run(
                [
                    str(get_dnscrypt_bin()),
                    "-check",
                    "-config",
                    str(DNSCRYPT_CONF),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if checked.returncode != 0:
                HOST.atomic_write(DNSCRYPT_CONF, previous)
                return False
            restarted = HOST.systemd("restart", "dnscrypt-proxy")
            if restarted.returncode != 0:
                HOST.atomic_write(DNSCRYPT_CONF, previous)
                HOST.systemd("restart", "dnscrypt-proxy")
                return False
            return True
        except Exception:
            HOST.atomic_write(DNSCRYPT_CONF, previous)
            return False

    @staticmethod
    def resolution_probe(
        *,
        domains: tuple[str, ...],
    ) -> list[tuple[str, int | None]]:
        """Resolve test domains and return their query latency."""
        results: list[tuple[str, int | None]] = []
        for domain in domains:
            try:
                response = HOST.run(
                    [
                        "dig",
                        "@127.0.0.1",
                        f"-p{DNSCRYPT_PORT}",
                        domain,
                        "+time=3",
                        "+tries=1",
                        "+noall",
                        "+stats",
                    ],
                    text=True,
                    timeout=5,
                )
                match = re.search(
                    r"Query time:\s*(\d+)\s*msec",
                    str(response.stdout or ""),
                )
                results.append(
                    (domain, int(match.group(1)) if match else None),
                )
            except Exception:
                results.append((domain, None))
        return results

    def install(self) -> bool:
        was_installed = self._installed()
        if not was_installed:
            if HOST.run(["apt-get", "update", "-qq"], timeout=60).returncode != 0:
                return False
            if HOST.run(
                ["apt-get", "install", "-y", "-qq", "dnscrypt-proxy"], timeout=60,
            ).returncode != 0:
                return False

        # Preserve an existing administrator/user configuration.  A freshly
        # installed distro config is replaced because HYDRA requires port 5300.
        if not was_installed or not DNSCRYPT_CONF.exists():
            self._write_default_config()
        service = HOST.run(["systemctl", "enable", "--now", "dnscrypt-proxy"])
        return service.returncode == 0

    def uninstall(self) -> bool:
        HOST.systemd("stop", "dnscrypt-proxy")
        HOST.systemd("disable", "dnscrypt-proxy")
        removed = HOST.run(
            ["apt-get", "remove", "-y", "-qq", "dnscrypt-proxy"], timeout=60,
        )
        if removed.returncode != 0:
            return False
        if DNSCRYPT_CONF.exists():
            DNSCRYPT_CONF.unlink(missing_ok=True)
        return True

    def repair_installation(self, *, enabled: bool) -> bool:
        """Reinstall the package while retaining HYDRA and user settings."""
        previous = DNSCRYPT_CONF.read_bytes() if DNSCRYPT_CONF.exists() else None
        repaired = HOST.run(
            ["apt-get", "install", "--reinstall", "-y", "-qq", "dnscrypt-proxy"],
            timeout=60,
        )
        if repaired.returncode != 0:
            if previous is not None:
                HOST.atomic_write(DNSCRYPT_CONF, previous)
            return False
        if previous is not None:
            HOST.atomic_write(DNSCRYPT_CONF, previous)
        else:
            self._write_default_config()
        action = [
            "systemctl", "enable" if enabled else "disable", "--now", "dnscrypt-proxy",
        ]
        return HOST.run(action).returncode == 0

    def snapshot(self, state: PluginStateAccess):
        runtime = HOST.systemd("is-active", "dnscrypt-proxy")
        return {
            "config": DNSCRYPT_CONF.read_bytes() if DNSCRYPT_CONF.exists() else None,
            "running": runtime.returncode == 0,
        }

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        previous = snapshot or {}
        config = previous.get("config")
        if config is None:
            DNSCRYPT_CONF.unlink(missing_ok=True)
        else:
            HOST.atomic_write(DNSCRYPT_CONF, config)
        if previous.get("running"):
            result = HOST.systemd("restart", "dnscrypt-proxy")
        else:
            result = HOST.systemd("stop", "dnscrypt-proxy")
        return result.returncode == 0

    def _write_default_config(self) -> None:
        """Пишет базовый конфиг DNSCrypt-proxy."""
        conf = f"""
listen_addresses = ['127.0.0.1:{DNSCRYPT_PORT}']
server_names = ['quad9-dnscrypt-ip4-filter-pri', 'cloudflare']
max_clients = 250
force_tcp = false
timeout = 3000
keepalive = 30
cert_refresh_delay = 240
fallback_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
log_level = 2
use_syslog = true

[sources]
  [sources.'public-resolvers']
  urls = [
      'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
      'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
  ]
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
"""
        HOST.atomic_write(DNSCRYPT_CONF, conf)

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        """Возвращает DNS-конфиг для Sing-Box."""
        dns_config = {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dnscrypt-local",
                    "server": "127.0.0.1",
                    "server_port": DNSCRYPT_PORT,
                }
            ],
            "rules": [],
        }
        return ConfigFragment(dns=dns_config)

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        installed = self._installed()
        running = False
        plugin_state = state.protocols.get(self.meta.name) if state else None
        enabled = plugin_state.enabled if plugin_state else DNSCRYPT_CONF.exists()
        if installed:
            r = HOST.systemd("is-active", "dnscrypt-proxy")
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=running,
            port=DNSCRYPT_PORT,
        )

    @staticmethod
    def _installed() -> bool:
        return Path("/usr/sbin/dnscrypt-proxy").exists() or Path("/usr/bin/dnscrypt-proxy").exists()

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {}

    def on_enable(self, state: PluginStateAccess) -> None:
        # Не затираем выбранные пользователем server_names при каждом toggle.
        if not DNSCRYPT_CONF.exists():
            self._write_default_config()
        enabled = HOST.systemd("enable", "dnscrypt-proxy")
        started = HOST.systemd("start", "dnscrypt-proxy")
        if enabled.returncode != 0 or started.returncode != 0:
            raise RuntimeError("Не удалось включить или запустить dnscrypt-proxy")

    def on_disable(self, state: PluginStateAccess) -> None:
        stopped = HOST.systemd("stop", "dnscrypt-proxy")
        disabled = HOST.systemd("disable", "dnscrypt-proxy")
        if stopped.returncode != 0 or disabled.returncode != 0:
            raise RuntimeError("Не удалось остановить или отключить dnscrypt-proxy")
