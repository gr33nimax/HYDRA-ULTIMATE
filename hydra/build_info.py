"""Immutable release provenance stamped by the transactional updater."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


BUILD_INFO_PATH = Path(__file__).parents[1] / ".hydra-build.json"
_CHANNELS = frozenset({"main", "dev", "debug"})
_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class BuildInfo:
    channel: str
    revision: str | None


def get_build_info() -> BuildInfo:
    """Return a stamped official build identity or the truthful local fallback."""
    try:
        raw = json.loads(BUILD_INFO_PATH.read_text(encoding="utf-8"))
        channel = raw.get("channel")
        revision = raw.get("revision")
    except (OSError, ValueError, TypeError):
        return BuildInfo(channel="local", revision=None)
    if channel not in _CHANNELS or not isinstance(revision, str) or not _SHA.fullmatch(revision):
        return BuildInfo(channel="local", revision=None)
    return BuildInfo(channel=channel, revision=revision)
