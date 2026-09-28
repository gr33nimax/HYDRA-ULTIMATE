"""Pure release-layout and archive validation for the VK headless creator."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path


_HASH_RE = re.compile(r"(?:/join/|join/)([^/?#\s]+)")
_MAX_CREATOR_BINARY_SIZE = 128 * 1024 * 1024


def extract_call_hash(value: str) -> str:
    match = _HASH_RE.search(str(value or "").strip())
    if match is None:
        raise ValueError("creator returned an invalid VK call link")
    return match.group(1)


def release_layout(machine: str) -> tuple[str, str]:
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


def creator_payload(archive: Path, member_name: str) -> bytes:
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


__all__ = ["creator_payload", "extract_call_hash", "release_layout"]
