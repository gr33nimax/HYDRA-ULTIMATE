"""Shared test isolation for code that normally manages a Linux host."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_host_filesystem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Keep unit tests unprivileged and side-effect free on CI runners."""
    from hydra.core import sni_router, state
    from hydra.plugins.fail2ban import plugin as fail2ban_plugin
    from hydra.plugins.honeypot import plugin as honeypot_plugin
    from hydra.plugins.warp import plugin as warp_plugin
    from hydra.services import sync_agent
    from hydra.utils import firewall

    state_dir = tmp_path / "state"
    monkeypatch.setattr(state, "STATE_DIR", state_dir)
    monkeypatch.setattr(state, "STATE_FILE", state_dir / "state.json")
    monkeypatch.setattr(sync_agent, "SYNC_LOCK", tmp_path / "run" / "sync-agent.lock")
    monkeypatch.setattr(sync_agent, "WARP_CACHE_FILE", tmp_path / "warp_external.json")
    monkeypatch.setattr(sync_agent, "SYNC_LOG", tmp_path / "sync-agent.log")
    monkeypatch.setattr(warp_plugin, "WARP_PROFILES_DIR", tmp_path / "warp-profiles")
    monkeypatch.setattr(sni_router, "CADDY_LOG_DIR", tmp_path / "caddy-log")
    monkeypatch.setattr(sni_router, "DECOY_LOG", tmp_path / "caddy-log" / "decoy-access.log")
    monkeypatch.setattr(sni_router, "CADDY_CFG_DIR", tmp_path / "caddy-config")
    monkeypatch.setattr(fail2ban_plugin, "AWG_DYNAMIC_DEBUG_PATHS", ())
    monkeypatch.setattr(fail2ban_plugin, "AWG_DEBUG_SERVICE", tmp_path / "fail2ban-awg-debug.service")
    monkeypatch.setattr(honeypot_plugin, "HONEYPOT_SCRIPT", tmp_path / "bin" / "hydra-honeypot.py")
    monkeypatch.setattr(honeypot_plugin, "HONEYPOT_SERVICE", tmp_path / "systemd" / "hydra-honeypot.service")
    monkeypatch.setattr(honeypot_plugin, "HONEYPOT_STATE", tmp_path / "state" / "honeypot.json")
    monkeypatch.setattr(honeypot_plugin, "HONEYPOT_LOG", tmp_path / "log" / "hydra-honeypot.log")
    monkeypatch.setattr(honeypot_plugin, "HONEYPOT_LOGROTATE", tmp_path / "logrotate" / "hydra-honeypot")
    monkeypatch.setattr(firewall, "persist", lambda: None)
