"""Typed Telemt settings and pure TOML rendering for the pinned upstream contract."""

from __future__ import annotations

from dataclasses import dataclass
import re

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_PORT
from .credentials import derive_secret, derive_username
from .migration import preview as migration_preview

__all__ = ["TelemtSettings", "plan_configuration", "render_toml", "settings_from_state"]

_NETWORKS = frozenset({"auto", "ipv4", "ipv6", "dual_stack"})
_LOG_LEVELS = frozenset({"normal", "debug"})
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _validate_domain(value: str) -> str:
    domain = value.strip().lower()
    labels = domain.rstrip(".").split(".")
    if (
        not domain
        or len(domain.rstrip(".")) > 253
        or len(labels) < 2
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("Telemt TLS domain must be a valid hostname")
    return domain.rstrip(".")


@dataclass(frozen=True)
class TelemtSettings:
    """The complete, intentionally bounded Hydra-facing Telemt configuration."""

    port: int
    tls_domain: str
    network: str = "auto"
    use_middle_proxy: bool = False
    log_level: str = "normal"

    def __post_init__(self) -> None:
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("Telemt port must be between 1 and 65535")
        object.__setattr__(self, "tls_domain", _validate_domain(self.tls_domain))
        if self.network not in _NETWORKS:
            raise ValueError(f"unsupported Telemt network mode: {self.network}")
        if not isinstance(self.use_middle_proxy, bool):
            raise ValueError("Telemt MiddleProxy setting must be boolean")
        if self.log_level not in _LOG_LEVELS:
            raise ValueError(f"unsupported Telemt log level: {self.log_level}")


def _require_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"Telemt {name} must be an integer")
    return value


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Telemt {name} must be a string")
    return value


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"Telemt {name} must be boolean")
    return value


def _network_from_legacy(config: dict) -> str:
    if "network" in config:
        return _require_str(config["network"], "network")
    ipv4 = _require_bool(config.get("ipv4", True), "ipv4")
    ipv6 = _require_bool(config.get("ipv6", False), "ipv6")
    if ipv4 and ipv6:
        return "dual_stack"
    return "ipv6" if ipv6 else "ipv4"


def settings_from_state(state: PluginStateAccess) -> TelemtSettings:
    """Map new and legacy persisted plugin state to validated settings."""
    protocol = state.protocols.get("telemt")
    config = protocol.config if protocol else {}
    migration = migration_preview(config)
    if not migration.is_compatible:
        raise ValueError("Telemt legacy settings require migration: " + ", ".join(migration.blockers))
    domain = config.get("tls_domain", state.network.domain or "google.com")
    advanced = config.get("advanced", {})
    if not isinstance(advanced, dict):
        raise ValueError("Telemt advanced settings must be an object")
    return TelemtSettings(
        port=_require_int(config.get("port", DEFAULT_PORT), "port"),
        tls_domain=_require_str(domain, "TLS domain"),
        network=_require_str(advanced.get("network", _network_from_legacy(config)), "network"),
        use_middle_proxy=_require_bool(
            advanced.get("use_middle_proxy", config.get("use_middle_proxy", False)),
            "MiddleProxy setting",
        ),
        log_level=_require_str(advanced.get("log_level", "normal"), "log level"),
    )


def _listeners(network: str) -> tuple[str, ...]:
    if network == "ipv6":
        return ("::",)
    if network == "dual_stack":
        return ("0.0.0.0", "::")
    return ("0.0.0.0",)


def render_toml(settings: TelemtSettings, users: dict[str, str]) -> str:
    """Render only the reviewed Telemt 3.5.7 TOML surface."""
    lines = [
        f'log_level = "{settings.log_level}"',
        "",
        "[general]",
        f"use_middle_proxy = {str(settings.use_middle_proxy).lower()}",
        "",
        "[general.modes]",
        "classic = false",
        "secure = false",
        "tls = true",
        "",
        "[general.links]",
        'show = "*"',
        "",
        "[server]",
        f"port = {settings.port}",
        "",
    ]
    for address in _listeners(settings.network):
        lines.extend(("[[server.listeners]]", f'ip = "{address}"', ""))
    lines.extend(
        (
            "[censorship]",
            f'tls_domain = "{settings.tls_domain}"',
            "mask = true",
            "tls_emulation = true",
            'tls_front_dir = "tlsfront"',
            "",
            "[access.users]",
        )
    )
    lines.extend(f'{name} = "{secret}"' for name, secret in sorted(users.items()))
    return "\n".join(lines) + "\n"


def build_toml(
    port: int,
    ipv4: bool,
    ipv6: bool,
    tls_domain: str,
    users: dict[str, str],
    use_middle_proxy: bool = False,
    client_mss: str = "",
) -> str:
    """Compatibility wrapper; client_mss is intentionally no longer rendered."""
    del client_mss
    network = "dual_stack" if ipv4 and ipv6 else "ipv6" if ipv6 else "ipv4"
    return render_toml(
        TelemtSettings(
            port=port,
            tls_domain=tls_domain,
            network=network,
            use_middle_proxy=use_middle_proxy,
        ),
        users,
    )


def plan_configuration(state: PluginStateAccess) -> tuple[str, ConfigFragment]:
    settings = settings_from_state(state)
    users = {derive_username(user.uuid): derive_secret(user.uuid) for user in state.users if not user.blocked}
    return render_toml(settings, users), ConfigFragment(nft_tproxy_ports=[settings.port])
