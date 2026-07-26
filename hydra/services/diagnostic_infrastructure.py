"""Local-host adapter for diagnostic network, clock, and filesystem probes."""
from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from hydra.services.diagnostics import DiagnosticOperations, HttpProbeResult


IP_VERSION_SELECTOR = threading.local()
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def original_getaddrinfo(
    host: str,
    port: int | str | None,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> Sequence[object]:
    return _ORIGINAL_GETADDRINFO(host, port, family, type, proto, flags)


def address_family(version: int | None, fallback: int = 0) -> int:
    if version == 4:
        return socket.AF_INET
    if version == 6:
        return socket.AF_INET6
    return fallback


def _filtered_getaddrinfo(
    host: str,
    port: int | str | None,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
):
    selected = getattr(IP_VERSION_SELECTOR, "ip_version", None)
    return original_getaddrinfo(
        host,
        port,
        address_family(selected, family),
        type,
        proto,
        flags,
    )


def install_address_filter() -> None:
    """Install the selector once; owning the process mutation in infrastructure."""

    if socket.getaddrinfo is not _filtered_getaddrinfo:
        socket.getaddrinfo = _filtered_getaddrinfo


def _error_result(exc: BaseException) -> HttpProbeResult:
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read()
        except Exception:
            body = b""
        return HttpProbeResult(
            status=int(exc.code),
            body=body,
            error_kind="http",
            error_detail=str(exc),
        )
    if isinstance(exc, ssl.SSLError):
        return HttpProbeResult(error_kind="tls", error_detail=str(exc))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return HttpProbeResult(error_kind="timeout", error_detail=str(exc))
    if isinstance(exc, ConnectionResetError):
        return HttpProbeResult(error_kind="reset", error_detail=str(exc))
    if isinstance(exc, ConnectionRefusedError):
        return HttpProbeResult(error_kind="refused", error_detail=str(exc))
    if isinstance(exc, urllib.error.URLError):
        reason = str(exc.reason)
        lowered = reason.lower()
        if "timed out" in lowered or "timeout" in lowered:
            kind = "timeout"
        elif "reset" in lowered:
            kind = "reset"
        elif "refused" in lowered:
            kind = "refused"
        elif "not known" in lowered or "resolve" in lowered:
            kind = "dns"
        else:
            kind = "url"
        return HttpProbeResult(error_kind=kind, error_detail=reason)
    return HttpProbeResult(error_kind="other", error_detail=str(exc))


class HostDiagnosticOperations(DiagnosticOperations):
    """Use Python's standard library behind the diagnostic capability port."""

    @property
    def pipe(self) -> object:
        return subprocess.PIPE

    @property
    def devnull(self) -> object:
        return subprocess.DEVNULL

    @property
    def stdout(self) -> object:
        return subprocess.STDOUT

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        timeout: float = 2.0,
        verify_tls: bool = True,
    ) -> HttpProbeResult:
        request = urllib.request.Request(
            url,
            headers=dict(headers or {}),
            data=data,
            method=method,
        )
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(
                request,
                context=context,
                timeout=timeout,
            ) as response:
                return HttpProbeResult(
                    status=int(getattr(response, "status", 0) or 0),
                    body=response.read(),
                    headers=dict(getattr(response, "headers", {}) or {}),
                )
        except Exception as exc:
            return _error_result(exc)

    def resolve_addresses(self, host: str) -> tuple[str, ...]:
        addresses = socket.getaddrinfo(host, None)
        return tuple(str(item[4][0]) for item in addresses)

    def ipv6_available(self) -> bool:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as stream:
                stream.settimeout(1.0)
                stream.connect(("2001:4860:4860::8888", 53))
            return True
        except Exception:
            return False

    def port_listening(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True

    def tcp_connect(self, host: str, port: int, timeout: float) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.settimeout(timeout)
                stream.connect((host, port))
            return True
        except Exception:
            return False

    def read_json_file(self, path: str) -> Any:
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, "r", encoding="utf-8") as handle:
            import json

            return json.load(handle)

    def path_exists(self, path: str) -> bool:
        return os.path.exists(path)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary)

    def monotonic(self) -> float:
        return time.monotonic()

    def wall_time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def url_hostname(self, url: str) -> str:
        return str(urlparse(url).hostname or "")

    def download_speed_mbps(
        self,
        url: str,
        *,
        timeout: float = 3.0,
        duration: float = 4.0,
        chunk_size: int = 65_536,
    ) -> float:
        try:
            start_time = time.time()
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                bytes_downloaded = 0
                elapsed = 0.0
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    bytes_downloaded += len(chunk)
                    elapsed = time.time() - start_time
                    if elapsed >= duration:
                        break
                if bytes_downloaded and elapsed == 0.0:
                    elapsed = time.time() - start_time
                if elapsed == 0:
                    return 0.0
                return (bytes_downloaded * 8) / elapsed / 1_000_000
        except Exception:
            return 0.0


HOST_DIAGNOSTICS = HostDiagnosticOperations()


def legacy_dependency(name: str) -> Any:
    """Resolve modules retained as patch points by the old public facade."""

    dependencies = {
        "os": os,
        "shutil": shutil,
        "socket": socket,
        "subprocess": subprocess,
        "time": time,
        "urllib": urllib,
    }
    try:
        return dependencies[name]
    except KeyError as exc:
        raise AttributeError(name) from exc


install_address_filter()
