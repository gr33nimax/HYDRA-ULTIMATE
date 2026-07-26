"""Runtime side effects for TrustTunnel."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import PluginState
from hydra.plugins.context import PluginStateAccess


def on_enable(
    state: PluginStateAccess,
    *,
    transport_of: Callable[[PluginState | None], str],
    validate: Callable[..., list[str]],
    resolve_certs: Callable[
        [str, PluginState | None],
        tuple[str, str],
    ],
    remove_iptables_rules: Callable[[], None],
) -> None:
    protocol = state.protocols.get("trusttunnel")
    if not protocol:
        raise ValueError("TrustTunnel configuration is missing")

    selected_transport = transport_of(protocol)
    domain = str(protocol.config.get("domain", "")).strip()
    if not domain:
        raise ValueError(
            "Домен TrustTunnel не настроен; задайте "
            "protocols.trusttunnel.config.domain перед включением",
        )

    errors = validate(
        state,
        require_cert=False,
        prospective_enable=True,
    )
    if errors:
        raise ValueError("; ".join(errors))

    cert_file, key_file = resolve_certs(domain, protocol)
    if not cert_file or not key_file:
        raise ValueError(
            f"TLS material for {domain} must be prepared "
            "by the application service"
        )

    from hydra.utils.firewall import open_tcp

    open_tcp(443, "trusttunnel")
    if selected_transport in ("quic", "both"):
        from hydra.utils.firewall import open_udp

        open_udp(443, "udp-quic-mux")
    remove_iptables_rules()


def remove_iptables_rules(host) -> None:
    """Remove obsolete port-wide accounting rules."""
    for chain in ("INPUT", "OUTPUT"):
        result = host.run(
            ["iptables", "-S", chain],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            if "trusttunnel-" not in line:
                continue
            parts = line.split()
            if parts and parts[0] == "-A":
                parts[0] = "-D"
                host.run(
                    ["iptables"] + parts,
                    capture_output=True,
                )
