"""SNI and endpoint policy for ShadowTLS."""
from __future__ import annotations

from collections.abc import Callable

from hydra.plugins.context import PluginStateAccess


def normalized_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def validate_handshake_sni(
    value: str,
    state: PluginStateAccess,
    *,
    normalize: Callable[[str], str] = normalized_host,
) -> str:
    handshake_sni = normalize(value)
    if not handshake_sni:
        raise ValueError(
            "SNI домен обязателен для маскировки ShadowTLS!"
        )

    own_hosts = {
        normalize(state.network.domain),
        normalize(state.network.sub_domain),
        normalize(state.network.server_ip),
    }
    for name, protocol in state.protocols.items():
        if name == "shadowtls" or not protocol.enabled:
            continue
        own_hosts.add(
            normalize(protocol.config.get("domain", ""))
        )

    own_hosts.discard("")
    if handshake_sni in own_hosts:
        raise ValueError(
            f"SNI {handshake_sni} принадлежит этому серверу. "
            "Для ShadowTLS укажите сторонний TLS 1.3 домен, "
            "иначе возникает циклическое подключение."
        )
    return handshake_sni


def probe_handshake_sni(
    handshake_sni: str,
    timeout: float,
    *,
    socket_module,
    ssl_module,
) -> None:
    """Verify that the target completes a valid TLS 1.3 handshake."""
    context = ssl_module.create_default_context()
    context.minimum_version = ssl_module.TLSVersion.TLSv1_3
    try:
        with socket_module.create_connection(
            (handshake_sni, 443),
            timeout=timeout,
        ) as raw:
            with context.wrap_socket(
                raw,
                server_hostname=handshake_sni,
            ) as tls:
                if tls.version() != "TLSv1.3":
                    raise ValueError(
                        f"SNI {handshake_sni} "
                        "не согласовал TLS 1.3"
                    )
    except ValueError:
        raise
    except (OSError, ssl_module.SSLError) as exc:
        raise ValueError(
            f"SNI {handshake_sni} недоступен с этого VPS "
            f"по TLS 1.3: {exc}"
        ) from exc


def server_ip(
    state: PluginStateAccess,
    *,
    public_ip_provider: Callable[[], str],
    parse_ip: Callable[[str], object],
) -> str:
    value = (
        state.network.server_ip
        or public_ip_provider()
    ).strip()
    try:
        return str(parse_ip(value))
    except ValueError as exc:
        raise ValueError(
            "Для ShadowTLS не удалось определить "
            "публичный IP сервера"
        ) from exc


def url_host(
    value: str,
    *,
    parse_ip: Callable[[str], object],
) -> str:
    address = parse_ip(value)
    return (
        f"[{address}]"
        if getattr(address, "version") == 6
        else str(address)
    )


def set_handshake_sni(
    state: PluginStateAccess,
    value: str,
    *,
    validate: Callable[[str, PluginStateAccess], str],
    probe: Callable[[str], None],
) -> bool:
    """Validate and update desired state without persistence side effects."""
    handshake_sni = validate(value, state)
    probe(handshake_sni)
    protocol = state.protocols.get("shadowtls")
    if protocol is None:
        return False
    protocol.config["handshake_sni"] = handshake_sni
    return True
