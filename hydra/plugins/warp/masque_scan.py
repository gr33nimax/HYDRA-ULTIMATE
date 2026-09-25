"""Bounded WARPSCOUT adapter; scan observations never become desired state."""

from __future__ import annotations

import ipaddress
import json
import math
import platform
import re
import shutil
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

from hydra.contracts import JsonValue
from hydra.core.host import HOST, HostBackend
from hydra.plugins.base import HealthResult
from hydra.plugins.context import PluginStateAccess
from hydra.utils.downloader import download_github_asset_filtered, extract_tarball, verify_elf

ACCOUNT = Path("/var/lib/hydra/warpscout/account.json")
WARPSCOUT_BIN = Path("/usr/local/bin/warpscout")
WARPSCOUT_REPO = "vernette/warpscout"
PROBE_PORT = 11880
_HEADER = re.compile(r"^# WARP endpoints: (\d+) working / (\d+) probed$")


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def install_warpscout(*, on_failure: Callable[[str], None] | None = None) -> bool:
    """Digest-verify and atomically install the warpscout binary from GitHub.

    warpscout is a third-party MASQUE scanner published as a per-arch tar.gz
    whose name carries the version, so the asset is matched by its
    ``_linux_<arch>.tar.gz`` suffix. The download must carry a SHA-256 digest;
    nothing replaces the installed binary until a verified ELF is produced.
    """
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"aarch64", "arm64"} else "amd64"
    suffix = f"_linux_{arch}.tar.gz"
    destination = Path(tempfile.mkdtemp(prefix="hydra-warpscout-"))
    try:
        archive = destination / "warpscout.tar.gz"
        reasons: list[str] = []
        if not download_github_asset_filtered(
            WARPSCOUT_REPO,
            lambda name: name.endswith(suffix),
            archive,
            require_unique=True,
            require_digest=True,
            on_error=reasons.append,
        ):
            _report(on_failure, reasons[-1] if reasons else "не удалось скачать релиз warpscout")
            return False
        extracted = destination / "extracted"
        try:
            extract_tarball(archive, extracted)
            found = next(
                (item for item in extracted.rglob("*") if item.is_file() and item.name == "warpscout"),
                None,
            )
        except (OSError, ValueError, tarfile.TarError) as exc:
            _report(on_failure, f"не удалось распаковать архив warpscout: {exc}")
            return False
        if found is None:
            _report(on_failure, "в архиве warpscout нет бинарника warpscout")
            return False
        if not verify_elf(found):
            _report(on_failure, "загруженный warpscout не является исполняемым ELF")
            return False
        pending = WARPSCOUT_BIN.with_suffix(".pending")
        try:
            WARPSCOUT_BIN.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(found, pending)
            pending.chmod(0o755)
            if not verify_elf(pending):
                pending.unlink(missing_ok=True)
                _report(on_failure, "проверка подготовленного warpscout не прошла")
                return False
            pending.replace(WARPSCOUT_BIN)
        except OSError as exc:
            pending.unlink(missing_ok=True)
            _report(on_failure, f"не удалось установить warpscout: {exc}")
            return False
        return True
    finally:
        _remove_tree(destination)


def remove_warpscout() -> bool:
    """Remove the warpscout binary and its account directory."""
    WARPSCOUT_BIN.unlink(missing_ok=True)
    _remove_tree(ACCOUNT.parent)
    return True


def _report(on_failure: Callable[[str], None] | None, message: str) -> None:
    if on_failure is None:
        return
    try:
        on_failure(message)
    except Exception:
        pass


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

    @staticmethod
    def install_warpscout_binary() -> bool:
        return install_warpscout()

    @staticmethod
    def remove_warpscout_binary() -> bool:
        return remove_warpscout()


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
