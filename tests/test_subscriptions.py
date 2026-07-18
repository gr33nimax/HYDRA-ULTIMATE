"""tests/test_subscriptions.py — Тесты для генератора подписок v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import base64
import json
import sys
import zlib
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.services.subscriptions.generator import (
    generate_links,
    generate_base64_sub,
    generate_singbox_config,
    generate_nekobox_sub,
    generate_throne_sub,
    resolve_subscription_format,
    serialize_nekobox_config,
    generate_client_config,
)
from hydra.core.state import AppState, User
from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment


class MockTransport(BasePlugin):
    """Тестовый TRANSPORT-плагин."""
    meta = PluginMeta(
        name="mock-transport",
        description="Mock transport",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self) -> PluginStatus:
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def client_link(self, user: User, state: AppState) -> str:
        return f"mock://{user.email}@example.com"

    def generate_client_config(self, user: User, state: AppState) -> str:
        return json.dumps({
            "outbounds": [{
                "type": "mock",
                "tag": f"mock-{user.email}",
                "server": "example.com",
            }],
        })


class MockNoLink(BasePlugin):
    """Транспорт без client_link."""
    meta = PluginMeta(
        name="mock-no-link",
        description="No link transport",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self) -> PluginStatus:
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def client_link(self, user: User, state: AppState) -> str:
        return ""

    def generate_client_config(self, user: User, state: AppState) -> str:
        return ""


def _make_state(users: list | None = None) -> AppState:
    state = AppState()
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "uu1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


# ═════════════════════════════════════════════════════════════════════════════
#  generate_links
# ═════════════════════════════════════════════════════════════════════════════

def test_generate_links_with_enabled_plugin():
    p = MockTransport()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        links = generate_links(user, state)
        assert links == ["mock://a@x.com@example.com"]


def test_generate_links_empty_when_no_plugins():
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[]):
        links = generate_links(user, state)
        assert links == []


def test_generate_links_skips_empty():
    p1 = MockTransport()
    p2 = MockNoLink()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[p1, p2]):
        links = generate_links(user, state)
        assert links == ["mock://a@x.com@example.com"]


# ═════════════════════════════════════════════════════════════════════════════
#  generate_base64_sub
# ═════════════════════════════════════════════════════════════════════════════

def test_generate_base64_sub():
    import base64
    p = MockTransport()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        encoded = generate_base64_sub(user, state)
        decoded = base64.b64decode(encoded).decode()
        assert "mock://a@x.com@example.com" in decoded


# ═════════════════════════════════════════════════════════════════════════════
#  generate_singbox_config
# ═════════════════════════════════════════════════════════════════════════════

def test_generate_singbox_config_includes_outbounds():
    p = MockTransport()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        config = generate_singbox_config(user, state)
        assert len(config["outbounds"]) >= 2
        assert config["outbounds"][0]["type"] == "mock"
        assert config["outbounds"][0]["tag"] == "mock-a@x.com"
        assert config["outbounds"][-1]["type"] == "direct"
        assert config["route"]["final"] == "mock-a@x.com"


def test_generate_singbox_config_deduplicates_direct_outbound():
    p = MockTransport()
    user = _make_user("a@x.com")
    state = _make_state([user])
    p.generate_client_config = MagicMock(return_value=json.dumps({
        "outbounds": [
            {"type": "trojan", "tag": "trojan-out"},
            {"type": "direct", "tag": "direct"},
        ],
    }))

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        config = generate_singbox_config(user, state)

    assert [o["tag"] for o in config["outbounds"]].count("direct") == 1
    assert config["route"]["final"] == "trojan-out"


def test_generate_singbox_config_base_structure():
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.enabled", return_value=[]):
        config = generate_singbox_config(user, state)
        assert "log" in config
        assert "inbounds" in config
        assert "outbounds" in config
        assert "route" in config
        assert config["outbounds"] == [{"type": "direct", "tag": "direct"}]


def test_generate_throne_sub_wraps_shadowtls_chain_as_custom_config():
    user = _make_user("a@x.com")
    state = _make_state([user])
    p = MockTransport()
    p.meta = PluginMeta(
        name="shadowtls",
        description="ShadowTLS",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
    )
    p.generate_client_config = MagicMock(return_value=json.dumps({
        "outbounds": [
            {"type": "trojan", "tag": "trojan-out", "detour": "shadowtls-out"},
            {"type": "shadowtls", "tag": "shadowtls-out"},
        ],
        "route": {"final": "trojan-out"},
    }))
    raw_links = "\n".join([
        "naive+https://u:p@example.com:443#naive",
        "trojan://inner@203.0.113.10:443?plugin=shadow-tls&plugin-opts=x#shadow",
        "",
    ])

    with patch(
        "hydra.services.subscriptions.generator.generate_base64_sub",
        return_value=base64.b64encode(raw_links.encode()).decode(),
    ), patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        subscription = generate_throne_sub(user, state)

    links = base64.b64decode(subscription).decode().splitlines()
    assert links[0].startswith("naive+https://")
    assert not any(link.startswith("trojan://") for link in links)
    custom_link = next(link for link in links if link.startswith("json://shadowtls#"))
    encoded = custom_link.split("#", 1)[1]
    encoded += "=" * (-len(encoded) % 4)
    wrapper = json.loads(base64.urlsafe_b64decode(encoded))
    config = json.loads(wrapper["config"])

    assert wrapper["type"] == "custom"
    assert wrapper["subtype"] == "fullconfig"
    assert config["route"]["final"] == "trojan-out"
    assert config["outbounds"][0]["detour"] == "shadowtls-out"
    assert config["inbounds"][0]["type"] == "mixed"


def test_serialize_nekobox_config_matches_configbean_kryo_format():
    config = '{"outbounds":[{"type":"trojan","tag":"trojan-out","detour":"shadowtls-out"}]}'
    assert serialize_nekobox_config(config, "test ShadowTLS") == (
        "sn://config?eNpjYGBgMDQy1zMAwo0WLAxgcI6xWim_tCQpvzQvpVjJKrpaqaSyIFXJSqmkKD8r"
        "MU9JR6kkMR3O1QUqBQqlpJbklxYBRYszElPyy0tyisEStbG1jEAjS1KLSxSCwTIhP"
        "pcbGwHRcCU0"
    )


def test_generate_nekobox_sub_wraps_shadowtls_chain_as_native_config():
    user = _make_user("a@x.com")
    state = _make_state([user])
    p = MockTransport()
    p.meta = PluginMeta(
        name="shadowtls",
        description="ShadowTLS",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
    )
    p.generate_client_config = MagicMock(return_value=json.dumps({
        "outbounds": [
            {"type": "trojan", "tag": "trojan-out", "detour": "shadowtls-out"},
            {"type": "shadowtls", "tag": "shadowtls-out"},
        ],
        "route": {"final": "trojan-out"},
    }))
    raw_links = "\n".join([
        "naive+https://u:p@example.com:443#naive",
        "trojan://inner@203.0.113.10:443?plugin=shadow-tls&plugin-opts=x#shadow",
        "",
    ])

    with patch(
        "hydra.services.subscriptions.generator.generate_base64_sub",
        return_value=base64.b64encode(raw_links.encode()).decode(),
    ), patch("hydra.services.subscriptions.generator.enabled", return_value=[p]):
        subscription = generate_nekobox_sub(user, state)

    links = base64.b64decode(subscription).decode().splitlines()
    assert links[0].startswith("naive+https://")
    assert not any(link.startswith("trojan://") for link in links)
    assert links[1].startswith("sn://config?")

    encoded = links[1].split("?", 1)[1] + "=" * (-len(links[1].split("?", 1)[1]) % 4)
    data = zlib.decompress(base64.urlsafe_b64decode(encoded))
    assert b'"detour":"shadowtls-out"' in data
    assert b'"type":"tun"' in data
    assert b'"address":["172.19.0.1/28","fdfe:dcba:9876::1/126"]' in data
    assert b'inet4_address' not in data
    assert b'inet6_address' not in data


def test_resolve_subscription_format_uses_explicit_override_then_user_agent():
    assert resolve_subscription_format("base64", "NekoBox/Android/1.4.2") == "base64"
    assert resolve_subscription_format(None, "NekoBox/Android/1.4.2") == "nekobox"
    assert resolve_subscription_format("auto", "Throne/1.0") == "throne"
    assert resolve_subscription_format(None, "curl/8") == "base64"


# ═════════════════════════════════════════════════════════════════════════════
#  generate_client_config
# ═════════════════════════════════════════════════════════════════════════════

def test_generate_client_config_unknown_protocol():
    user = _make_user("a@x.com")
    state = _make_state([user])
    result = generate_client_config(user, state, "nonexistent")
    assert result == ""


def test_generate_client_config_mock():
    p = MockTransport()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.services.subscriptions.generator.get", return_value=p):
        result = generate_client_config(user, state, "mock-transport")
        parsed = json.loads(result)
        assert parsed["outbounds"][0]["type"] == "mock"


def test_generate_awg_sn_link():
    conf = """[Interface]
PrivateKey = MOaSN+H5tfDmpWIGmv2nXBZwV5NEezzjoDu6mZyvqXI=
Address = 10.68.68.3/32
DNS = 1.1.1.1
MTU = 1280
Jc = 3
Jmin = 49
Jmax = 114
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = 7e8ef37f3541bf9be0d39ec98635bc6190e26e818ffbe5bede1b39a3612c81

[Peer]
PublicKey = C0reEXAcpsdLQvUDhukTJLc2g5iq0QP3pEg3wTspkn0=
PresharedKey = rHbKMxS+vx+lecmMFErDnwPy+av9zJFbBmsXpxQLnnI=
Endpoint = 31.77.203.66:51821
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    from hydra.services.subscriptions.generator import generate_awg_sn_link
    expected = "sn://awg?eNpFjrFSg0AYhE8dH8JnYAbv-MNxFBRGiCFCDJOoTDoOjqjxkIABQhfeh8bC1t6nEhvd2Z1vq509RQgBUQ1D1TCo9FN-I0SwStmv4RI-ev8uWs6Vqf6e2jJ_dG9kpWXheF0_6HNHtO3Lm72ncn2odqFr9de4EE54Fedl4gXVvf20365mXqxt9OcdDhaQOxuoV2W-zbDVF1N-6zdLpWqUVxFLf-IUdlYvDkpUme1swseyDPMm8LLMtS6Gn-gcoePZQDKkQP_qSKf9dehGX4ZgIgUjBX1EeGpygRMwRWwyCjqPKTGx0KhghKUpFzoXiSAczAgo0WJGjoNOhqkBP0NhUSE"
    assert generate_awg_sn_link(conf, "") == expected

