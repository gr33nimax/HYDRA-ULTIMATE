"""Pure state migration adding the selectable server kernel."""
from __future__ import annotations

import copy


def migrate_v9_to_v10(data: dict) -> dict:
    """Keep existing installations on the released Sing-Box Extended core."""
    migrated = copy.deepcopy(data)
    kernel = migrated.setdefault("kernel", {})
    kernel.setdefault("provider", "sing-box-extended")
    kernel.setdefault("channel", "stable")
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            config.setdefault("mode", "p2p")
    wdtt = protocols.get("wdtt", {}) if isinstance(protocols, dict) else {}
    if isinstance(wdtt, dict):
        config = wdtt.setdefault("config", {})
        if isinstance(config, dict):
            config.setdefault("dtls_port", 56000)
            config.setdefault("wg_port", 56001)
    migrated["version"] = 10
    return migrated


__all__ = ["migrate_v9_to_v10"]
