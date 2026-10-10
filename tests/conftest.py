"""Shared test isolation for code that normally manages a Linux host."""
from __future__ import annotations

from pathlib import Path
import os
import sys

import pytest

# Collection imports application adapters; their live discovery threads are not
# part of unit tests and must never disclose the runner's network identity.
os.environ["HYDRA_DISABLE_BACKGROUND_PROBES"] = "1"


@pytest.fixture(autouse=True)
def isolate_host_filesystem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    """Keep unit tests unprivileged and side-effect free on CI runners."""
    from hydra.core import sni_router, state
    from hydra.plugins.fail2ban import plugin as fail2ban_plugin
    from hydra.plugins.antidpi import plugin as antidpi_plugin
    from hydra.plugins.honeypot import plugin as honeypot_plugin
    from hydra.plugins.warp import plugin as warp_plugin
    from hydra.services import sync_agent
    from hydra.utils import firewall
    from hydra.utils import net

    # Client renderers also discover an IP synchronously when a fixture omits it.
    # Give those adapters a reserved test address; explicit per-test mocks win.
    original_public_ip = net.public_ip
    for name, module in tuple(sys.modules.items()):
        if name.startswith("hydra.") and name != "hydra.utils.net" and getattr(module, "public_ip", None) is original_public_ip:
            monkeypatch.setattr(module, "public_ip", lambda: "203.0.113.254")
    # The utility's own tests already mock subprocess.run and exercise the real
    # fallback loop. Every other test, including imports made during execution,
    # receives the offline provider.
    if not request.node.name.startswith("test_public_ip_"):
        monkeypatch.setattr(net, "public_ip", lambda: "203.0.113.254")

    state_dir = tmp_path / "state"
    monkeypatch.setattr(state, "STATE_DIR", state_dir)
    monkeypatch.setattr(state, "STATE_FILE", state_dir / "state.json")
    monkeypatch.setattr(sync_agent, "SYNC_LOCK", tmp_path / "run" / "sync-agent.lock")
    monkeypatch.setattr(sync_agent, "SYNC_LOG", tmp_path / "sync-agent.log")
    monkeypatch.setattr(
        warp_plugin,
        "WARP_EXTERNAL_CACHE",
        tmp_path / "warp_external.json",
    )
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
    # AntiScan consumes an address inventory, not a live public-IP lookup.
    # Dedicated network utility tests retain their own mocked discovery checks.
    monkeypatch.setattr(antidpi_plugin, "host_ip_addresses", lambda configured=(): ("127.0.0.1", "::1", *configured))
