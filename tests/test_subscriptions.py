"""tests/test_subscriptions.py — Тесты для генератора подписок v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.services.subscriptions.generator import (
    generate_links,
    generate_base64_sub,
    generate_singbox_config,
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
