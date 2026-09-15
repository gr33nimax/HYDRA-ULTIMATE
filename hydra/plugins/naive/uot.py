"""Desired UDP-over-TCP mode for NaiveProxy and the build it implies."""

from __future__ import annotations

from pathlib import Path

from hydra.core.sni_router_install import (
    NAIVE_FORWARD_PROXY_MODULE,
    NAIVE_FORWARD_PROXY_STOCK_MODULE,
)
from hydra.plugins.context import PluginStateAccess


# Only a UoT-capable build accepts this directive. Probing with it is how the
# installed binary is classified, so the setting cannot drift from the file.
UOT_PROBE = ":8080 {\n forward_proxy {\n  upstream socks5://127.0.0.1:1080\n  passthrough_uot\n }\n}\n"
PLAIN_PROBE = ":8080 {\n forward_proxy {\n  upstream socks5://127.0.0.1:1080\n }\n}\n"


def uot_enabled(state: PluginStateAccess) -> bool:
    """Read the desired UoT mode; an absent value means enabled."""
    protocol = state.protocols.get("naive")
    if protocol is None or not protocol.config:
        return True
    return bool(protocol.config.get("uot", True))


def normalize_uot(value: object) -> bool | None:
    """Accept the spellings an operator or a command line may carry."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "on", "yes", "вкл"}:
            return True
        if text in {"0", "false", "off", "no", "выкл"}:
            return False
    return None


def build_module(uot: bool) -> str:
    """The forwardproxy module a build for this mode must come from."""
    return NAIVE_FORWARD_PROXY_MODULE if uot else NAIVE_FORWARD_PROXY_STOCK_MODULE


def write_probe(path: Path, uot: bool) -> None:
    """Write the Caddyfile a build for this mode has to validate."""
    path.write_text(UOT_PROBE if uot else PLAIN_PROBE, encoding="utf-8")
