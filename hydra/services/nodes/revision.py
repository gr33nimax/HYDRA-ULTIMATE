"""Read the exact public branch head before a node installation or upgrade."""

from __future__ import annotations

import json
import urllib.request
from urllib.parse import quote

from hydra.contracts.node_validation import checked_node_branch, checked_node_revision


MAX_REVISION_RESPONSE_BYTES = 65536
MAX_BOOTSTRAP_SCRIPT_BYTES = 262144
_BOOTSTRAP_MARKER = "HYDRA_ROLE"


def fetch_bootstrap_script(revision: str) -> str:
    """Read the installer exactly as it is at the revision being installed.

    The base streams its own bootstrap script to the node, but the node downloads its
    tree from the pinned revision. Those two must be the same commit: a base running a
    newer branch once installed a script that referenced a file the older tree did not
    contain yet, and the install died on `install: cannot stat`. Taking the script from
    the revision removes that class of mismatch entirely.
    """
    revision = checked_node_revision(revision, context="revision")
    request = urllib.request.Request(
        f"https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/{revision}/bootstrap.sh",
        headers={"Accept": "text/plain", "User-Agent": "HYDRA-Node-Installer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_BOOTSTRAP_SCRIPT_BYTES + 1)
        if len(raw) > MAX_BOOTSTRAP_SCRIPT_BYTES:
            raise ValueError("installer script exceeds the supported limit")
        script = raw.decode("utf-8")
    except Exception as exc:
        raise ValueError("Не удалось получить установочный скрипт выбранной ревизии из GitHub") from exc
    if _BOOTSTRAP_MARKER not in script or not script.startswith("#!"):
        raise ValueError("Установочный скрипт выбранной ревизии выглядит повреждённым")
    return script


def revision_supports_node_mode(revision: str) -> bool:
    """Whether this revision carries the node role at all.

    A branch that predates the node role has no control service to install, and the
    install would fail only after it already replaced the VPS's HYDRA. The plan asks
    this once, before anything is touched.
    """
    revision = checked_node_revision(revision, context="revision")
    request = urllib.request.Request(
        f"https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/{revision}/deploy/hydra-node-control.service",
        headers={"Accept": "text/plain", "User-Agent": "HYDRA-Node-Installer"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


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
