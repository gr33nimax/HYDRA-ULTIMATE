"""Host adapter capabilities for the standalone creator qWDTT pool."""
from __future__ import annotations

import json
import platform
import re
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from hydra.utils.downloader import download_github_asset_filtered, verify_elf


QWDTT_POOL_DIR = Path("/var/lib/hydra/headless-creator/vk/qwdtt")
QWDTT_POOL_STATE = QWDTT_POOL_DIR / "state.json"
CREATOR_BINARY = Path("/usr/local/bin/headless-vk-creator")
CREATOR_UNIT = Path("/etc/systemd/system/hydra-headless-creator-vk@.service")
CREATOR_REPO = "kulikov0/whitelist-bypass"
CREATOR_COUNT = 4
LEGACY_UNIT = Path("/etc/systemd/system/wdtt-headless-creator@.service")
LEGACY_POOL_DIR = Path("/etc/wdtt/headless")
LEGACY_COOKIES_FILE = Path("/etc/hydra/cookiesvk/cookies-vk.json")
INTERMEDIATE_UNIT = Path("/etc/systemd/system/hydra-vk-call-creator@.service")
INTERMEDIATE_POOL_DIR = Path("/var/lib/hydra/calls/vk/qwdtt")
LEGACY_LINK_FILE = Path("/etc/wdtt/qwdtt_link.txt")
_HASH_RE = re.compile(r"(?:/join/|join/)([^/?#\s]+)")
_MAX_CREATOR_BINARY_SIZE = 128 * 1024 * 1024


@dataclass(frozen=True)
class LegacyCreatorSnapshot:
    files: dict[Path, tuple[bytes, int]]
    active_units: tuple[str, ...]
    enabled_units: tuple[str, ...]


@dataclass(frozen=True)
class CreatorPoolStage:
    generation: str
    previous_generation: str
    previous_metadata: dict[str, object]


def extract_call_hash(value: str) -> str:
    match = _HASH_RE.search(str(value or "").strip())
    if match is None:
        raise ValueError("creator returned an invalid VK call link")
    return match.group(1)


def _release_layout(machine: str) -> tuple[str, str]:
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
    normalized = str(machine or "").strip().lower()
    if normalized not in layouts:
        raise ValueError(
            f"unsupported headless creator architecture: {normalized or 'unknown'}",
        )
    return layouts[normalized]


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


class HeadlessCreatorPoolInfrastructureMixin:
    """Blue/green VK creator lifecycle owned outside protocol plugins."""

    def install_creator(self) -> tuple[bool, str]:
        existing = self.host.which(str(self.creator_binary))
        if existing and verify_elf(Path(existing)):
            return True, "headless creator is already installed"
        if existing:
            return False, "existing headless creator is not a valid ELF binary"
        asset_arch, member_name = _release_layout(platform.machine())
        asset_name = f"whitelist-bypass-cli-linux-{asset_arch}.zip"
        with tempfile.TemporaryDirectory(prefix="hydra-headless-creator-") as work:
            archive = Path(work) / asset_name
            if not download_github_asset_filtered(
                self.creator_repo,
                lambda name: name == asset_name,
                archive,
            ):
                return False, f"failed to download verified release asset: {asset_name}"
            payload = _creator_payload(archive, member_name)
            candidate = Path(work) / "headless-vk-creator"
            candidate.write_bytes(payload)
            if not verify_elf(candidate):
                return False, "downloaded headless creator is not an ELF binary"
            self.host.atomic_write(self.creator_binary, payload, mode=0o755)
        return True, "headless creator installed"

    def creator_units(
        self,
        *,
        generation: str | None = None,
        legacy: bool = False,
    ) -> list[str]:
        prefix = "wdtt-headless-creator" if legacy else "hydra-headless-creator-vk"
        if legacy:
            generation = ""
        elif generation is None:
            generation = str(self.pool_metadata().get("generation", ""))
        instances = [
            f"{generation}-{index}" if generation else str(index)
            for index in range(1, self.creator_count + 1)
        ]
        return [f"{prefix}@{instance}.service" for instance in instances]

    def call_files(self, *, generation: str | None = None) -> list[Path]:
        if generation is None:
            generation = str(self.pool_metadata().get("generation", ""))
        prefix = f"{generation}-" if generation else ""
        return [
            self.pool_dir / f"{prefix}{index}.call.txt"
            for index in range(1, self.creator_count + 1)
        ]

    def _write_creator_unit(self) -> None:
        command = (
            f"{self.creator_binary} --cookies {self.cookies_file} "
            f"--resources default --write-file {self.pool_dir}/%i.call.txt"
        )
        content = (
            "[Unit]\nDescription=HYDRA VK call creator %i\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={command}\nRestart=on-failure\nRestartSec=5\n"
            "NoNewPrivileges=true\nUMask=0077\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        self.host.atomic_write(self.creator_unit, content, mode=0o644)

    def refresh_creator_pool(self, *, previous: list[str] | None = None) -> list[str]:
        self.validate_credentials()
        self.host.ensure_directory(self.pool_dir, mode=0o700)
        self._write_creator_unit()
        if self.host.run(["systemctl", "daemon-reload"]).returncode != 0:
            raise RuntimeError("systemd daemon-reload failed")
        metadata = self.pool_metadata()
        active = str(metadata.get("generation", ""))
        target = "b" if active == "a" else "a"
        self._stop_generation(target)
        self._pool_stage = CreatorPoolStage(target, active, metadata)
        try:
            for unit in self.creator_units(generation=target):
                if self.host.run(["systemctl", "enable", unit]).returncode != 0:
                    raise RuntimeError(f"failed to enable {unit}")
                if self.host.run(["systemctl", "restart", unit]).returncode != 0:
                    raise RuntimeError(f"failed to restart {unit}")
            for _ in range(60):
                hashes = self._read_hashes_for(target)
                if hashes and (not previous or hashes != previous):
                    return hashes
                time.sleep(1)
            raise TimeoutError("headless creator did not return four VK call links")
        except Exception:
            self.rollback_creator_pool()
            raise

    def read_creator_hashes(self) -> list[str]:
        generation = str(self.pool_metadata().get("generation", ""))
        return self._read_hashes_for(generation)

    def _read_hashes_for(self, generation: str) -> list[str]:
        hashes: list[str] = []
        for path in self.call_files(generation=generation):
            try:
                lines = [
                    line
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                hashes.append(extract_call_hash(lines[-1]))
            except (OSError, ValueError, IndexError):
                return []
        unique = len(set(hashes)) == len(hashes)
        return hashes if len(hashes) == self.creator_count and unique else []

    def pool_metadata(self) -> dict[str, object]:
        try:
            value = json.loads(self.pool_state_file.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def commit_pool(self, hashes: list[str]) -> None:
        if len(hashes) != self.creator_count or len(set(hashes)) != len(hashes):
            raise ValueError("exactly four unique VK call hashes are required")
        self.host.ensure_directory(self.pool_dir, mode=0o700)
        payload = {
            "hashes": hashes,
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
            "generation": self._pool_stage.generation if self._pool_stage else "",
        }
        self.host.atomic_write(
            self.pool_state_file,
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )

    def finalize_creator_pool(self) -> None:
        stage = self._pool_stage
        if stage is None:
            return
        if stage.previous_generation != stage.generation:
            self._stop_generation(stage.previous_generation)
        self._pool_stage = None

    def rollback_creator_pool(self) -> None:
        stage = self._pool_stage
        if stage is None:
            return
        self._stop_generation(stage.generation)
        if stage.previous_metadata:
            self.host.atomic_write(
                self.pool_state_file,
                json.dumps(stage.previous_metadata, ensure_ascii=False, indent=2) + "\n",
                mode=0o600,
            )
        else:
            self.host.remove_file(self.pool_state_file, missing_ok=True)
        self._pool_stage = None

    def _stop_generation(self, generation: str) -> list[str]:
        failures: list[str] = []
        for unit in self.creator_units(generation=generation):
            for action in ("stop", "disable"):
                if self.host.run(["systemctl", action, unit]).returncode != 0:
                    failures.append(f"{action} {unit}")
        for path in self.call_files(generation=generation):
            self.host.remove_file(path, missing_ok=True)
        return failures

    def stop_creator_pool(self) -> tuple[bool, str]:
        failures: list[str] = []
        for generation in ("", "a", "b"):
            failures.extend(self._stop_generation(generation))
        self._pool_stage = None
        if failures:
            return False, "failed to stop all creator services: " + ", ".join(failures)
        return True, "all VK creator calls stopped"

    def uninstall_creator_pool(self) -> tuple[bool, str]:
        ok, message = self.stop_creator_pool()
        if not ok:
            return ok, message
        self.host.remove_file(self.creator_unit, missing_ok=True)
        self.host.remove_file(self.pool_state_file, missing_ok=True)
        self.host.run(["systemctl", "daemon-reload"])
        return True, "VK creator pool uninstalled"

    def uninstall_creator(self) -> tuple[bool, str]:
        ok, message = self.uninstall_creator_pool()
        if not ok:
            return ok, message
        self.host.remove_file(self.creator_binary, missing_ok=True)
        return True, "headless creator uninstalled"

    def cleanup_legacy_creator(self) -> tuple[bool, str]:
        failures: list[str] = []
        for unit in self._legacy_units():
            known = self.host.run(["systemctl", "cat", unit]).returncode == 0
            if not known:
                continue
            for action in ("stop", "disable"):
                result = self.host.run(["systemctl", action, unit])
                if result.returncode != 0:
                    failures.append(f"{action} {unit}")
        if failures:
            return False, "failed to stop legacy creator: " + ", ".join(failures)
        self.host.remove_file(LEGACY_UNIT, missing_ok=True)
        self.host.remove_file(INTERMEDIATE_UNIT, missing_ok=True)
        for index in range(1, self.creator_count + 1):
            self.host.remove_file(LEGACY_POOL_DIR / f"{index}.call.txt", missing_ok=True)
            for generation in ("", "a", "b"):
                prefix = f"{generation}-" if generation else ""
                self.host.remove_file(
                    INTERMEDIATE_POOL_DIR / f"{prefix}{index}.call.txt",
                    missing_ok=True,
                )
        self.host.remove_file(LEGACY_POOL_DIR / "state.json", missing_ok=True)
        self.host.remove_file(INTERMEDIATE_POOL_DIR / "state.json", missing_ok=True)
        self.host.run(["systemctl", "daemon-reload"])
        return True, "legacy creator installations removed"

    def snapshot_legacy_creator(self) -> LegacyCreatorSnapshot:
        paths = [
            LEGACY_UNIT,
            INTERMEDIATE_UNIT,
            LEGACY_COOKIES_FILE,
            LEGACY_LINK_FILE,
            LEGACY_POOL_DIR / "state.json",
            INTERMEDIATE_POOL_DIR / "state.json",
            *(LEGACY_POOL_DIR / f"{index}.call.txt" for index in range(1, self.creator_count + 1)),
            *(
                INTERMEDIATE_POOL_DIR / f"{generation}-{index}.call.txt"
                for generation in ("a", "b")
                for index in range(1, self.creator_count + 1)
            ),
        ]
        files: dict[Path, tuple[bytes, int]] = {}
        for path in paths:
            try:
                files[path] = (path.read_bytes(), path.stat().st_mode & 0o777)
            except OSError:
                continue
        active: list[str] = []
        enabled: list[str] = []
        for unit in self._legacy_units():
            if self.host.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0:
                active.append(unit)
            if self.host.run(["systemctl", "is-enabled", "--quiet", unit]).returncode == 0:
                enabled.append(unit)
        return LegacyCreatorSnapshot(files, tuple(active), tuple(enabled))

    def restore_legacy_creator(self, snapshot: LegacyCreatorSnapshot) -> None:
        for path, (content, mode) in snapshot.files.items():
            self.host.atomic_write(path, content, mode=mode)
        self.host.run(["systemctl", "daemon-reload"])
        for unit in snapshot.enabled_units:
            self.host.run(["systemctl", "enable", unit])
        for unit in snapshot.active_units:
            self.host.run(["systemctl", "start", unit])

    def _legacy_units(self) -> list[str]:
        units = self.creator_units(legacy=True)
        units.extend(
            f"hydra-vk-call-creator@{generation}-{index}.service"
            for generation in ("a", "b")
            for index in range(1, self.creator_count + 1)
        )
        return units


CallsCreatorInfrastructureMixin = HeadlessCreatorPoolInfrastructureMixin


__all__ = [
    "CREATOR_BINARY",
    "CREATOR_COUNT",
    "CREATOR_REPO",
    "CREATOR_UNIT",
    "CallsCreatorInfrastructureMixin",
    "CreatorPoolStage",
    "LegacyCreatorSnapshot",
    "HeadlessCreatorPoolInfrastructureMixin",
    "QWDTT_POOL_DIR",
    "QWDTT_POOL_STATE",
    "extract_call_hash",
]
