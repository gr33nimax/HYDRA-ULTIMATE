"""Bounded WARPSCOUT adapter; scan observations never become desired state."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import tempfile
from pathlib import Path

from hydra.contracts import JsonValue
from hydra.core.host import HOST, HostBackend
from hydra.plugins.base import HealthResult
from hydra.plugins.context import PluginStateAccess

ACCOUNT = Path("/var/lib/hydra/warpscout/account.json")
PROBE_PORT = 11880
_HEADER = re.compile(r"^# WARP endpoints: (\d+) working / (\d+) probed$")


def endpoint_value(address: object, port: object) -> dict[str, JsonValue]:
    try:
        if not isinstance(address, str):
            raise ValueError("invalid address")
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("MASQUE: адрес должен быть IP-адресом") from exc
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("MASQUE: порт должен быть от 1 до 65535")
    return {"address": str(ip), "port": port}


class MasqueScannerActions:
    @staticmethod
    def register_masque_scanner() -> bool:
        register_masque(HOST)
        return True

    @staticmethod
    def scan_masque_endpoints() -> list[dict[str, object]]:
        return scan_masque(HOST)


def set_masque_endpoint(state: PluginStateAccess, *, address: str, port: int) -> bool:
    config = state.protocols["warp"].config
    if address == "" and port == 0:
        return config.pop("masque_endpoint", None) is not None
    chosen = endpoint_value(address, port)
    if config.get("masque_endpoint") == chosen:
        return False
    config["masque_endpoint"] = chosen
    return True


def scanner_status(host: HostBackend, account: Path = ACCOUNT) -> dict[str, bool]:
    return {
        "installed": bool(host.which("warpscout")),
        "account_ready": account.is_file() and not account.is_symlink() and not account.parent.is_symlink(),
    }


def healthcheck(state: PluginStateAccess, host: HostBackend) -> HealthResult:
    from hydra.core.singbox import is_running

    if not is_running():
        return HealthResult(False, "Служба Sing-Box не работает", "error")
    selected = state.protocols.get("warp")
    if not selected or not selected.config.get("masque_endpoint"):
        return HealthResult(True)
    curl = host.which("curl")
    if not curl:
        return HealthResult(False, "Не найден curl для проверки WARP", "error")
    try:
        result = host.run(
            [
                curl,
                "--silent",
                "--show-error",
                "--fail",
                "--noproxy",
                "",
                "--max-time",
                "12",
                "--max-filesize",
                "1024",
                "--proxy",
                f"socks5h://127.0.0.1:{PROBE_PORT}",
                "https://www.cloudflare.com/cdn-cgi/trace",
            ],
            timeout=18,
            text=True,
        )
    except (OSError, RuntimeError):
        return HealthResult(False, "Выбранный адрес WARP не отвечает", "error")
    if result.returncode != 0 or "warp=on" not in str(result.stdout or "").splitlines():
        return HealthResult(False, "Выбранный адрес WARP не отвечает", "error")
    return HealthResult(True)


def parse_report(text: str) -> list[dict[str, object]]:
    """Read only the working section of a -P report, never the torn-down rows."""
    lines = text.splitlines()
    match = _HEADER.fullmatch(lines[0]) if lines else None
    if match is None or "# TUN PING / LOSS" not in text:
        raise ValueError("Неизвестный формат отчёта warpscout")
    try:
        count, probed = (int(value) for value in match.groups())
    except ValueError as exc:
        raise ValueError("Некорректный заголовок отчёта warpscout") from exc
    if count > 4096 or count > probed:
        raise ValueError("Некорректное число адресов в отчёте warpscout")
    header = next((i for i, line in enumerate(lines) if line.startswith("ENDPOINT ") and "TUN PING" in line), None)
    if header is None:
        raise ValueError("В отчёте warpscout нет результатов поиска")
    result: list[dict[str, object]] = []
    for line in lines[header + 1 :]:
        if not line.strip():
            break
        parts = line.split()
        if len(parts) < 6:
            raise ValueError("Некорректная строка отчёта warpscout")
        try:
            address, raw_port = parts[0].rsplit(":", 1)
            endpoint = endpoint_value(address.strip("[]"), int(raw_port))
            ping = float(parts[2].removesuffix("ms"))
            loss = int(parts[3].removesuffix("%"))
            if (
                not 0 <= loss <= 100
                or not math.isfinite(ping)
                or ping <= 0
                or not parts[2].endswith("ms")
                or not parts[3].endswith("%")
                or not re.fullmatch(r"[A-Za-z0-9?_-]{1,12}", parts[4])
                or not re.fullmatch(r"[A-Za-z0-9?_-]{1,12}", parts[5])
            ):
                raise ValueError("invalid measurement")
        except (ValueError, IndexError) as exc:
            raise ValueError("Некорректный адрес или замер в отчёте warpscout") from exc
        result.append({**endpoint, "ping_ms": ping, "loss_percent": loss, "seen_as": parts[4], "node": parts[5]})
        if len(result) == count:
            break
    if len(result) != count:
        raise ValueError("Отчёт warpscout неполный")
    return result


def register_masque(host: HostBackend, account: Path = ACCOUNT) -> None:
    binary = host.which("warpscout")
    if not binary:
        raise RuntimeError("warpscout не установлен на VPS")
    if account.parent.is_symlink():
        raise RuntimeError("Небезопасный каталог аккаунта warpscout")
    host.ensure_directory(account.parent, mode=0o700)
    if account.is_symlink():
        raise RuntimeError("Небезопасный путь к аккаунту warpscout")
    if account.exists():
        return
    with tempfile.TemporaryDirectory(prefix=".register-", dir=account.parent) as directory:
        pending = Path(directory) / "account.json"
        result = host.run(
            [binary, "register", "-a", str(pending), "-relay", "none", "-plain"], cwd=directory, timeout=180
        )
        if result.returncode != 0 or not pending.is_file() or pending.is_symlink():
            raise RuntimeError("Не удалось создать аккаунт warpscout")
        try:
            registered = json.loads(pending.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError("Некорректный аккаунт warpscout") from exc
        if not isinstance(registered, dict) or not isinstance(registered.get("masque"), dict):
            raise RuntimeError("warpscout не создал MASQUE-устройство")
        host.atomic_copy(pending, account, mode=0o600)


def scan_masque(host: HostBackend, account: Path = ACCOUNT) -> list[dict[str, object]]:
    binary = host.which("warpscout")
    if not binary:
        raise RuntimeError("warpscout не установлен на VPS")
    if account.parent.is_symlink() or account.is_symlink() or not account.is_file():
        raise RuntimeError("Аккаунт warpscout не подготовлен")
    with tempfile.TemporaryDirectory(prefix="hydra-warp-scan-") as directory:
        report = Path(directory) / "result.txt"
        result = host.run(
            [binary, "scan", "-p", "masque", "-P", "-plain", "-a", str(account), "-o", str(report)],
            cwd=directory,
            timeout=300,
        )
        if result.returncode != 0:
            if "no MASQUE endpoint passed data" in str(result.stderr or ""):
                return []
            raise RuntimeError("Поиск WARP не удался; текущий адрес не изменён")
        if report.is_symlink() or not report.is_file() or report.stat().st_size > 128 * 1024:
            raise RuntimeError("Отчёт warpscout не получен или слишком велик")
        return parse_report(report.read_text(encoding="utf-8"))
