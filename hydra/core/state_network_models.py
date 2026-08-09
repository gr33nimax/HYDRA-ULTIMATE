"""Pure persisted network settings shared by the state aggregate."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NetworkConfig:
    """Persisted network settings that are not owned by a plugin."""

    domain: str = ""
    sub_domain: str = ""
    server_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dnscrypt_port: int = 5300
    tproxy_enabled: bool = False
    tproxy_port: int = 1081
    clash_api_enabled: bool = False
    clash_api_port: int = 9090
    clash_api_secret: str = ""


__all__ = ["NetworkConfig"]
