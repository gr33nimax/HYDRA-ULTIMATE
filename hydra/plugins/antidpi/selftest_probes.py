"""Network and native-client probes with explicit runtime dependencies."""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from hydra.core.state_models import AppState, User
from hydra.plugins.antidpi.selftest_targets import Target

PAYLOADS = (
    b"HYDRA-ANTIDPI-SELFTEST\r\n",
    (
        b"GET /__hydra_antidpi_selftest__ HTTP/1.1\r\n"
        b"Host: invalid.local\r\nConnection: close\r\n\r\n"
    ),
    (
        b"CONNECT selftest.invalid:443 HTTP/1.1\r\n"
        b"Host: selftest.invalid:443\r\n"
        b"Proxy-Authorization: Basic aW52YWxpZDppbnZhbGlk\r\n"
        b"Connection: close\r\n\r\n"
    ),
    b"\x16\x03\x03\x00\x08INVALID!",
    b"\x00\xff\x00\xffHYDRA-INVALID-HANDSHAKE",
)
SINGBOX_CLIENT_PROTOCOLS = {
    "anytls",
    "trusttunnel",
    "shadowtls",
    "hysteria2",
    "mieru",
    "naive",
    "snell",
}


class ClientConfigProvider(Protocol):
    """Public protocol boundary needed by the diagnostic client."""

    def client_config(
        self,
        state: AppState,
        name: str,
        user: User,
        **parameters: object,
    ) -> str: ...


class ProbeHost(Protocol):
    def which(self, name: str) -> str | None: ...
    def run(self, command: list[str], **options: object): ...
    def popen(self, command: list[str], **options: object): ...


def probe(
    target: Target,
    timeout: float = 0.8,
    extra_payloads: tuple[bytes, ...] = (),
) -> list[dict]:
    """Send bounded malformed payloads to one local target."""
    results = []
    for payload in (*PAYLOADS, *extra_payloads):
        started = time.monotonic()
        error = ""
        try:
            if target.transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(payload, (target.host, target.port))
            else:
                with socket.create_connection(
                    (target.host, target.port),
                    timeout=timeout,
                ) as raw:
                    stream = raw
                    if target.transport == "tls":
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        stream = context.wrap_socket(
                            raw,
                            server_hostname=target.sni,
                        )
                    stream.sendall(payload)
                    try:
                        stream.recv(256)
                    except (OSError, TimeoutError):
                        pass
        except (OSError, ssl.SSLError) as exc:
            error = f"{exc.__class__.__name__}: {exc}"
        results.append(
            {
                "transport": target.transport,
                "host": target.host,
                "port": target.port,
                "sni": target.sni,
                "payload_bytes": len(payload),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "error": error,
            },
        )
    return results


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def invalid_client_config(
    state: AppState,
    protocol: str,
    listen_port: int,
    *,
    protocols: ClientConfigProvider | None,
) -> tuple[dict | None, str]:
    """Build an ephemeral invalid client through the public protocol service."""
    if protocol not in SINGBOX_CLIENT_PROTOCOLS:
        return None, "native_client_unavailable"
    if protocols is None:
        return None, "protocol_service_unavailable"
    user = next(
        (candidate for candidate in state.users if not candidate.blocked),
        None,
    )
    if user is None:
        return None, "no_unblocked_user"
    try:
        config = json.loads(protocols.client_config(state, protocol, user))
    except (TypeError, ValueError) as exc:
        return None, f"invalid_generated_config: {exc}"
    except Exception as exc:
        return None, f"client_generation_failed: {exc.__class__.__name__}"
    if not isinstance(config, dict) or not isinstance(
        config.get("outbounds"),
        list,
    ):
        return None, "client_config_unavailable"
    changed = _invalidate_outbounds(config, protocol)
    if not changed:
        return None, "credential_field_unavailable"
    config["inbounds"] = [
        {
            "type": "mixed",
            "tag": "hydra-selftest-in",
            "listen": "127.0.0.1",
            "listen_port": listen_port,
        },
    ]
    config.setdefault("log", {})["level"] = "debug"
    return config, "ready"


def _invalidate_outbounds(config: dict, protocol: str) -> bool:
    changed = False
    accepted_types = (
        {protocol}
        if protocol != "shadowtls"
        else {"shadowtls", "trojan"}
    )
    for outbound in config["outbounds"]:
        if (
            not isinstance(outbound, dict)
            or outbound.get("type") not in accepted_types
        ):
            continue
        outbound["server"] = "127.0.0.1"
        for field in ("password", "username", "psk"):
            if field in outbound:
                outbound[field] = f"HYDRA-INVALID-{field.upper()}"
                changed = True
        tls = outbound.get("tls")
        if isinstance(tls, dict):
            tls["insecure"] = True
    return changed


def socks_trigger(port: int) -> str:
    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=1.5,
        ) as stream:
            stream.sendall(b"\x05\x01\x00")
            if stream.recv(2) != b"\x05\x00":
                return "SOCKS negotiation rejected"
            stream.sendall(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
            stream.settimeout(2.0)
            stream.recv(32)
        return ""
    except (OSError, TimeoutError) as exc:
        return f"{exc.__class__.__name__}: {exc}"


def client_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] = "true"
    environment["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] = "true"
    return environment


def native_client_probe(
    state: AppState,
    protocol: str,
    *,
    protocols: ClientConfigProvider | None,
    host: ProbeHost,
    config_builder: Callable[
        [AppState, str, int, ClientConfigProvider | None],
        tuple[dict | None, str],
    ],
) -> dict:
    if protocol == "naive":
        return native_naive_probe(state, host=host)
    executable = host.which("sing-box")
    if not executable:
        return {"status": "missing_sing_box", "started": False}
    listen_port = free_tcp_port()
    config, status = config_builder(
        state,
        protocol,
        listen_port,
        protocols,
    )
    if config is None:
        return {"status": status, "started": False}
    return _run_native_client(
        executable,
        config,
        listen_port,
        protocol=protocol,
        host=host,
    )


def _run_native_client(
    executable: str,
    config: dict,
    listen_port: int,
    *,
    protocol: str,
    host: ProbeHost,
) -> dict:
    with tempfile.TemporaryDirectory(
        prefix=f"hydra-{protocol}-client-",
    ) as temp_name:
        path = Path(temp_name) / "client.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        environment = client_environment()
        check = host.run(
            [executable, "check", "-c", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        if check.returncode != 0:
            detail = (
                check.stderr
                or check.stdout
                or "config check failed"
            ).strip()[-1000:]
            return {
                "status": "config_rejected",
                "started": False,
                "client_log": detail,
            }
        process = host.popen(
            [executable, "run", "-c", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        return _drive_native_client(process, listen_port)


def _drive_native_client(process, listen_port: int) -> dict:
    trigger_error = "client listener did not start"
    triggered = False
    output = ""
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and process.poll() is None:
            trigger_error = socks_trigger(listen_port)
            if not trigger_error.startswith("ConnectionRefusedError"):
                triggered = True
                break
            time.sleep(0.05)
        time.sleep(0.5)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            output, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=2)
    return {
        "status": "executed" if triggered else "client_failed",
        "started": True,
        "triggered": triggered,
        "returncode": process.returncode,
        "trigger_error": trigger_error,
        "client_log": str(output or "")[-2000:],
    }


def native_naive_probe(state: AppState, *, host: ProbeHost) -> dict:
    """Exercise Caddy Naive directly when sing-box lacks its client."""
    executable = host.which("curl")
    domain = str(state.network.domain or "").strip()
    if not executable:
        return {
            "status": "missing_curl",
            "started": False,
            "triggered": False,
        }
    if not domain:
        return {
            "status": "missing_domain",
            "started": False,
            "triggered": False,
        }
    result = host.run(
        [
            executable,
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--max-time",
            "5",
            "--proxy-insecure",
            "--resolve",
            f"{domain}:443:127.0.0.1",
            "--proxy",
            f"https://HYDRA-INVALID:HYDRA-INVALID@{domain}:443",
            "http://selftest.invalid/__hydra_antidpi_selftest__",
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    return {
        "status": "executed",
        "started": True,
        "triggered": True,
        "returncode": result.returncode,
        "client_log": str(result.stderr or result.stdout or "")[-1000:],
    }
