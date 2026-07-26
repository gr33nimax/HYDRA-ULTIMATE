"""Network and journal observations used by Telemt fallback."""

from __future__ import annotations

import re
import socket
import urllib.request
from collections.abc import Callable, Sequence
from threading import Thread


ME_ENDPOINTS: list[tuple[str, int]] = [
    ("149.154.175.50", 443),
    ("149.154.175.50", 8443),
    ("149.154.167.51", 443),
    ("149.154.167.51", 8443),
    ("149.154.175.100", 443),
    ("149.154.175.100", 8443),
    ("149.154.167.91", 443),
    ("149.154.167.91", 8443),
    ("91.108.4.100", 443),
    ("91.108.4.100", 8443),
]
PROXY_CONFIG_URL = "https://core.telegram.org/getProxyConfig"
PROXY_CONFIG_TIMEOUT = 5.0
ME_QUORUM = 0.34
PROBE_TCP_TIMEOUT = 5.0
ME_FAILURE_PATTERNS: tuple[str, ...] = (
    "All ME servers for DC",
    "ME server connection failed",
    "middle proxy init failed",
    "Failed to connect to ME",
    "ME pool exhausted",
)


def fetch_live_me_endpoints(
    url: str = PROXY_CONFIG_URL,
    timeout: float = PROXY_CONFIG_TIMEOUT,
    *,
    request_factory: Callable[..., object] = urllib.request.Request,
    open_url: Callable[..., object] = urllib.request.urlopen,
) -> list[tuple[str, int]]:
    """Fetch and parse Telegram's current middle-proxy endpoint list."""

    try:
        request = request_factory(
            url,
            headers={"User-Agent": "hydra-ultimate/telemt-fallback"},
        )
        with open_url(request, timeout=timeout) as response:  # type: ignore[attr-defined]
            text = response.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    endpoints: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for match in re.finditer(r"proxy_for\s+-?\d+\s+([\d.]+):(\d+)\s*;", text):
        endpoint = (match.group(1), int(match.group(2)))
        if endpoint not in seen:
            seen.add(endpoint)
            endpoints.append(endpoint)
    return endpoints


class MiddleProxyProbe:
    """Probe Telegram ME endpoints concurrently using TCP connect."""

    def __init__(
        self,
        endpoints: list[tuple[str, int]] = ME_ENDPOINTS,
        tcp_timeout: float = PROBE_TCP_TIMEOUT,
        quorum: float = ME_QUORUM,
        *,
        thread_factory: Callable[..., Thread] = Thread,
    ) -> None:
        self._endpoints = endpoints
        self._timeout = tcp_timeout
        self._quorum = quorum
        self._thread_factory = thread_factory

    def probe_one(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self._timeout):
                return True
        except (OSError, socket.timeout, ConnectionRefusedError):
            return False

    def probe_all(self) -> tuple[int, int]:
        results = [False] * len(self._endpoints)
        threads: list[Thread] = []

        def worker(index: int, host: str, port: int) -> None:
            results[index] = self.probe_one(host, port)

        for index, (host, port) in enumerate(self._endpoints):
            thread = self._thread_factory(
                target=worker,
                args=(index, host, port),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=self._timeout + 1)
        return sum(results), len(self._endpoints)

    def is_available(self) -> bool:
        available, total = self.probe_all()
        return bool(total) and available / total >= self._quorum

    def summary(self) -> str:
        available, total = self.probe_all()
        if not total:
            return "ME-серверы: список пуст"
        ratio = available / total
        endpoints = f"{available}/{total}"
        if ratio >= self._quorum:
            return f"ME-серверы доступны ({endpoints} endpoint'ов)"
        return (
            f"ME-серверы НЕДОСТУПНЫ ({endpoints} endpoint'ов "
            f"< кворум {self._quorum:.0%})"
        )


def journal_failure_lines(
    runner: Callable[..., object],
    *,
    lines: int,
    service: str,
    patterns: Sequence[str] = ME_FAILURE_PATTERNS,
) -> list[str]:
    """Find known ME failure signals in recent systemd journal output."""

    try:
        result = runner(
            [
                "journalctl",
                "-u",
                service,
                "-n",
                str(lines),
                "--no-pager",
                "--output=short",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode != 0:  # type: ignore[attr-defined]
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()  # type: ignore[attr-defined]
            if any(pattern.lower() in line.lower() for pattern in patterns)
        ]
    except Exception:
        return []
