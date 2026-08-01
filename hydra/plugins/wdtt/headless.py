"""VK headless-creator lifecycle and qWDTT master-link projection."""
from __future__ import annotations

import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from hydra.plugins.base import MaintenanceTask
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt.model import WdttEnvironment
from hydra.utils.downloader import (
    download_github_asset_filtered,
    verify_elf,
)


REFRESH_INTERVAL = 86_400
_HASH_RE = re.compile(r"(?:/join/|join/)([^/?#\s]+)")
_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_MAX_CREATOR_BINARY_SIZE = 128 * 1024 * 1024

HEADLESS_MAINTENANCE_TASKS = (
    MaintenanceTask(
        action="refresh_headless_creator",
        title="🔄 Обновление qWDTT-звонков",
        description="Раз в 24 часа пересоздавать четыре VK-звонка и ссылку",
        due_query="headless_creator_due",
        enabled_flag="sync_wdtt_headless_enabled",
        apply_on_success=False,
    ),
)


def _json(env: WdttEnvironment, value: object) -> str:
    return env.json_module.dumps(value, indent=2, ensure_ascii=False)


def normalize_cookies(raw: str, env: WdttEnvironment) -> str:
    """Convert a pasted JSON/header cookie value to creator JSON."""
    value = str(raw or "").strip()
    if not value:
        raise ValueError("VK cookies are required")
    candidate = Path(value)
    try:
        is_file = candidate.is_file()
    except OSError:
        is_file = False
    if is_file:
        value = candidate.read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("VK cookies file is empty")
    if value.startswith("[") or value.startswith("{"):
        parsed = env.json_module.loads(value)
        if isinstance(parsed, dict):
            parsed = parsed.get("cookies", [parsed])
        if not isinstance(parsed, list) or not parsed:
            raise ValueError("VK cookies JSON must contain a non-empty list")
        cookies = parsed
    else:
        cookies = []
        for item in value.split(";"):
            if "=" not in item:
                continue
            name, cookie_value = item.split("=", 1)
            name = name.strip()
            if name and _COOKIE_NAME_RE.fullmatch(name):
                cookies.append({"name": name, "value": cookie_value.strip()})
        if not cookies:
            raise ValueError("VK cookies must be JSON or name=value pairs")
    for item in cookies:
        if not isinstance(item, dict) or not str(item.get("name", "")).strip():
            raise ValueError("invalid VK cookie entry")
    return _json(env, cookies)


def extract_hash(link: str) -> str:
    """Extract one VK call token from a creator output line."""
    match = _HASH_RE.search(str(link or "").strip())
    if not match:
        raise ValueError("headless creator returned an invalid VK call link")
    return match.group(1)


def build_qwdtt_link(
    server_ip: str,
    dtls_port: int,
    password: str,
    hashes: list[str],
    *,
    workers: int = 16,
    local_port: int = 9000,
) -> str:
    """Build the single qWDTT profile used by the master password."""
    clean_hashes = [str(item).strip() for item in hashes if str(item).strip()]
    if len(clean_hashes) != 4 or len(set(clean_hashes)) != 4:
        raise ValueError("exactly four unique VK call hashes are required")
    name = quote(f"qWDTT-{server_ip}", safe="-._~")
    peer = quote(f"{server_ip}:{int(dtls_port)}", safe=":[]-._~")
    encoded_hashes = quote(",".join(clean_hashes), safe=",-._~")
    encoded_password = quote(str(password), safe="-._~")
    return (
        f"qwdtt://config?name={name}&peer={peer}&hashes={encoded_hashes}"
        f"&workers={int(workers)}&port={int(local_port)}&pass={encoded_password}"
    )


def _release_layout(machine: str) -> tuple[str, str]:
    normalized = str(machine or "").strip().lower()
    layouts = {
        "x86_64": ("x64", "headless-vk-creator"),
        "amd64": ("x64", "headless-vk-creator"),
        "i386": ("ia32", "headless-vk-creator"),
        "i686": ("ia32", "headless-vk-creator"),
        "x86": ("ia32", "headless-vk-creator"),
        "aarch64": ("arm", "arm64/headless-vk-creator"),
        "arm64": ("arm", "arm64/headless-vk-creator"),
        "armv7l": ("arm", "arm/headless-vk-creator"),
        "armv6l": ("arm", "arm/headless-vk-creator"),
        "mips": ("mips", "mips/headless-vk-creator"),
        "mipsle": ("mips", "mipsle/headless-vk-creator"),
        "mips64": ("mips", "mips64/headless-vk-creator"),
        "mips64le": ("mips", "mips64le/headless-vk-creator"),
    }
    try:
        return layouts[normalized]
    except KeyError as exc:
        raise ValueError(
            f"unsupported headless creator architecture: {normalized or 'unknown'}",
        ) from exc


def _creator_payload(archive: Path, member_name: str) -> bytes:
    try:
        with zipfile.ZipFile(archive) as bundle:
            member = bundle.getinfo(member_name)
            if member.is_dir() or not 0 < member.file_size <= _MAX_CREATOR_BINARY_SIZE:
                raise ValueError("invalid headless creator binary size")
            with bundle.open(member) as source:
                payload = source.read(_MAX_CREATOR_BINARY_SIZE + 1)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise ValueError("headless creator is missing from release archive") from exc
    if len(payload) != member.file_size or len(payload) > _MAX_CREATOR_BINARY_SIZE:
        raise ValueError("invalid headless creator binary size")
    return payload


def install(env: WdttEnvironment) -> tuple[bool, str]:
    """Install the latest verified creator release and prepare its private dir."""
    try:
        env.host.ensure_directory(env.headless_dir, mode=0o700)
        binary = env.headless_bin_path
        existing = env.host.which(str(binary))
        if existing and verify_elf(Path(existing)):
            return True, "headless creator is already installed"
        if existing:
            return False, f"existing headless creator is not an ELF binary: {binary}"
        asset_arch, member_name = _release_layout(env.platform_module.machine())
        asset_name = f"whitelist-bypass-cli-linux-{asset_arch}.zip"
        with tempfile.TemporaryDirectory(prefix="hydra-wdtt-headless-") as work:
            archive = Path(work) / asset_name
            downloaded = download_github_asset_filtered(
                env.headless_github_repo,
                lambda name: name == asset_name,
                archive,
            )
            if not downloaded:
                return False, f"failed to download verified release asset: {asset_name}"
            payload = _creator_payload(archive, member_name)
            candidate = Path(work) / "headless-vk-creator"
            candidate.write_bytes(payload)
            if not verify_elf(candidate):
                return False, "downloaded headless creator is not an ELF binary"
            env.host.atomic_write(binary, payload, mode=0o755)
        if not env.host.which(str(binary)):
            return False, f"installed headless creator is not executable: {binary}"
        return True, "headless creator installed"
    except (OSError, ValueError) as exc:
        return False, str(exc)


def _config(state: PluginStateAccess | None) -> dict:
    if state is None:
        return {}
    protocol = state.protocols.get("wdtt")
    return dict(protocol.config) if protocol else {}


def _configured(state: PluginStateAccess | None) -> bool:
    return bool(_config(state).get("headless_enabled", False))


def _metadata(env: WdttEnvironment) -> dict:
    if not env.headless_state_file.exists():
        return {}
    try:
        value = env.json_module.loads(
            env.headless_state_file.read_text(encoding="utf-8"),
        )
    except (OSError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_unit(env: WdttEnvironment, binary: Path) -> None:
    command = (
        f"{binary} --cookies {env.headless_cookies_file} "
        f"--resources default --write-file {env.headless_dir}/%i.call.txt"
    )
    content = (
        "[Unit]\nDescription=VK headless qWDTT creator %i\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"ExecStart={command}\nRestart=on-failure\nRestartSec=5\n"
        "NoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n"
    )
    env.host.atomic_write(env.headless_service_file, content, mode=0o644)


def _service_names(env: WdttEnvironment) -> list[str]:
    return [
        f"wdtt-headless-creator@{index}.service"
        for index in range(1, env.headless_call_count + 1)
    ]


def _restart_services(env: WdttEnvironment) -> bool:
    if env.host.run(
        ["systemctl", "daemon-reload"], capture_output=True,
    ).returncode != 0:
        return False
    for unit in _service_names(env):
        enabled = env.host.run(
            ["systemctl", "enable", unit], capture_output=True,
        )
        if enabled.returncode != 0:
            return False
        restarted = env.host.run(
            ["systemctl", "restart", unit], capture_output=True,
        )
        if restarted.returncode != 0:
            return False
    return True


def _call_files(env: WdttEnvironment) -> list[Path]:
    return [
        env.headless_dir / f"{index}.call.txt"
        for index in range(1, env.headless_call_count + 1)
    ]


def _read_hashes(env: WdttEnvironment) -> list[str]:
    hashes: list[str] = []
    for path in _call_files(env):
        if not path.exists():
            return []
        try:
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            hashes.append(extract_hash(lines[-1]))
        except (OSError, ValueError, IndexError):
            return []
    return hashes if len(set(hashes)) == env.headless_call_count else []


def _wait_hashes(
    env: WdttEnvironment,
    *,
    previous: list[str] | None = None,
) -> list[str]:
    for _ in range(60):
        hashes = _read_hashes(env)
        if (
            len(hashes) == env.headless_call_count
            and (
                not previous
                or all(current != old for current, old in zip(hashes, previous))
            )
        ):
            return hashes
        env.time_module.sleep(1)
    return []


def _password(env: WdttEnvironment, state: PluginStateAccess) -> str:
    try:
        data = _metadata_passwords(env)
        password = str(data.get("main_password", ""))
    except Exception:
        password = ""
    return password or str(_config(state).get("main_password", env.system_password))


def _metadata_passwords(env: WdttEnvironment) -> dict:
    if not env.passwords_file.exists():
        return {}
    value = env.json_module.loads(env.passwords_file.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _master_link(env: WdttEnvironment) -> str:
    try:
        return (
            env.headless_link_file.read_text(encoding="utf-8").strip()
            if env.headless_link_file.exists()
            else ""
        )
    except OSError:
        return ""


def status(env: WdttEnvironment, state: PluginStateAccess | None = None) -> dict:
    metadata = _metadata(env)
    hashes = list(metadata.get("hashes", []))
    return {
        "configured": _configured(state),
        "call_count": (
            env.headless_call_count
            if len(hashes) == env.headless_call_count
            else 0
        ),
        "refreshed_at": str(metadata.get("refreshed_at", "")),
        "link_ready": bool(_master_link(env)),
    }


def due(
    env: WdttEnvironment,
    *,
    state: PluginStateAccess | None = None,
    forced: bool = False,
) -> bool:
    if not _configured(state):
        return False
    if forced:
        return True
    metadata = _metadata(env)
    stored_hashes = list(metadata.get("hashes", []))
    live_hashes = _read_hashes(env)
    if live_hashes and live_hashes != stored_hashes:
        return True
    value = metadata.get("refreshed_at")
    if not value:
        return True
    try:
        refreshed = datetime.fromisoformat(str(value))
        if refreshed.tzinfo is None:
            refreshed = refreshed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - refreshed).total_seconds() >= REFRESH_INTERVAL
    except (TypeError, ValueError):
        return True


def _refresh(env: WdttEnvironment, state: PluginStateAccess) -> tuple[bool, str]:
    if not _configured(state):
        return False, "headless creator is disabled"
    binary_value = str(env.headless_bin_path).strip()
    binary = Path(binary_value)
    if not binary.is_absolute() or any(char.isspace() for char in binary_value):
        return False, "headless creator binary path must be absolute and whitespace-free"
    if not env.headless_cookies_file.exists():
        return False, "VK cookies are not configured"
    if not env.host.which(str(binary)):
        return False, f"headless creator binary is missing: {binary}"
    env.host.ensure_directory(env.headless_dir, mode=0o700)
    previous = _read_hashes(env)
    _write_unit(env, binary)
    if not _restart_services(env):
        return False, "failed to restart headless creator services"
    hashes = _wait_hashes(env, previous=previous)
    if len(hashes) != env.headless_call_count:
        return False, "headless creator did not return four VK call links"
    password = _password(env, state)
    server_ip = str(getattr(state.network, "server_ip", "") or env.public_ip())
    protocol = state.protocols.get("wdtt")
    dtls_port = int(protocol.config.get("dtls_port", env.default_dtls_port)) if protocol else env.default_dtls_port
    link = build_qwdtt_link(server_ip, dtls_port, password, hashes, local_port=env.local_tun_port)
    now = datetime.now(timezone.utc).isoformat()
    env.host.atomic_write(env.headless_link_file, link + "\n", mode=0o600)
    env.host.atomic_write(env.headless_state_file, _json(env, {"hashes": hashes, "refreshed_at": now}), mode=0o600)
    return True, "qWDTT master link updated"


def setup(env: WdttEnvironment, state: PluginStateAccess, cookies: str) -> tuple[bool, str]:
    normalized = normalize_cookies(cookies, env)
    installed, message = install(env)
    if not installed:
        return False, message
    env.host.ensure_directory(env.headless_dir, mode=0o700)
    previous = None
    if env.headless_cookies_file.exists():
        previous = env.headless_cookies_file.read_text(encoding="utf-8")
    env.host.atomic_write(env.headless_cookies_file, normalized + "\n", mode=0o600)
    result = _refresh(env, state)
    if not result[0] and previous is not None:
        env.host.atomic_write(env.headless_cookies_file, previous, mode=0o600)
    return result


def uninstall(env: WdttEnvironment) -> None:
    """Stop creator instances and remove their shared systemd unit."""
    for unit in _service_names(env):
        env.host.run(["systemctl", "stop", unit], capture_output=True)
        env.host.run(["systemctl", "disable", unit], capture_output=True)
    if env.headless_service_file.exists():
        env.headless_service_file.unlink()
    if env.headless_bin_path.exists():
        env.headless_bin_path.unlink()
    env.host.run(["systemctl", "daemon-reload"], capture_output=True)


class WdttHeadlessMixin:
    """Expose headless creator through the plugin contract."""

    def setup_headless_creator(self, *, cookies: str, state: PluginStateAccess) -> tuple[bool, str]:
        return setup(self._wdtt_env(), state, cookies)

    def refresh_headless_creator(self, *, state: PluginStateAccess) -> tuple[bool, str]:
        return _refresh(self._wdtt_env(), state)

    def headless_creator_status(self, *, state: PluginStateAccess | None = None) -> dict:
        return status(self._wdtt_env(), state)

    def headless_creator_link(self) -> str:
        """Return the secret-bearing link only through an explicit query."""
        return _master_link(self._wdtt_env())

    def headless_creator_due(
        self,
        *,
        state: PluginStateAccess | None = None,
        forced: bool = False,
    ) -> bool:
        return due(self._wdtt_env(), state=state, forced=forced)


__all__ = [
    "HEADLESS_MAINTENANCE_TASKS",
    "REFRESH_INTERVAL",
    "WdttHeadlessMixin",
    "build_qwdtt_link",
    "extract_hash",
    "normalize_cookies",
    "uninstall",
]
