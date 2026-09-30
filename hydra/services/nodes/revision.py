"""Read the exact public branch head before a node installation or upgrade."""

from __future__ import annotations

import json
import urllib.request
from urllib.parse import quote

from hydra.contracts.node_validation import checked_node_branch, checked_node_revision


MAX_REVISION_RESPONSE_BYTES = 65536


def resolve_branch_revision(branch: str) -> str:
    branch = checked_node_branch(branch, context="branch")
    request = urllib.request.Request(
        f"https://api.github.com/repos/gr33nimax/HYDRA-ULTIMATE/git/ref/heads/{quote(branch, safe='')}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "HYDRA-Node-Installer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(MAX_REVISION_RESPONSE_BYTES + 1)
        if len(raw) > MAX_REVISION_RESPONSE_BYTES:
            raise ValueError("branch response exceeds the supported limit")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("ref") != f"refs/heads/{branch}":
            raise ValueError("branch response does not match the selected branch")
        commit = payload.get("object")
        if not isinstance(commit, dict) or commit.get("type") != "commit":
            raise ValueError("branch response does not identify a commit")
        return checked_node_revision(commit.get("sha"), context="revision")
    except Exception as exc:
        raise ValueError("Не удалось получить SHA ветки из GitHub; установка или обновление не начаты") from exc
