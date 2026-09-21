"""tests/test_telemt_plugin.py — Тесты для Telemt MTProxy plugin v2."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.telemt.plugin import TelemtPlugin, CONFIG_FILE
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.plugins.invoker import PluginInvoker
from hydra.services.user_lifecycle import UserLifecycleOperations, UserTransport
from hydra.core.state import AppState, User, PluginState


def test_manager_toggle_uses_application_boundary():
    from typing import cast

    from hydra.plugins.telemt import manager as legacy_manager
    from hydra.services.application import ApplicationService
    from hydra.ui.plugin_managers import telemt as manager

    # The legacy path is the same module object, so exercising the canonical
    # module also covers it (and stays statically resolvable).
    assert legacy_manager is manager

    state = AppState(protocols={"telemt": PluginState(enabled=True, installed=True)})
    disable = Mock(return_value=True)
    app = cast(
        ApplicationService,
        SimpleNamespace(protocols=SimpleNamespace(disable=disable)),
    )

    assert manager._set_telemt_enabled(state, False, app) is True
    disable.assert_called_once_with(state, "telemt")


def test_disable_stops_and_disables_service():
    plugin = TelemtPlugin()
    state = _make_state()

    with patch("hydra.plugins.telemt.plugin.HOST.run") as run:
        plugin.on_disable(state)

    run.assert_called_once_with(
        ["systemctl", "disable", "--now", "telemt"],
        capture_output=True,
    )


def test_install_delegates_to_transactional_installer():
    plugin = TelemtPlugin()
    with patch("hydra.plugins.telemt.plugin.installation.install", return_value=True) as install:
        assert plugin.install() is True

    install.assert_called_once()


def _make_state(users: list | None = None, domain: str = "", server_ip: str = "1.2.3.4") -> AppState:
    state = AppState()
    state.network.domain = domain
    state.network.server_ip = server_ip
    state.protocols["telemt"] = PluginState(enabled=True, port=8443, config={})
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = TelemtPlugin()
    assert p.meta.name == "telemt"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False
    assert p.meta.capabilities.tls_domain_source == ""
    assert p.meta.capabilities.actions == ("update_binary",)


def test_plugin_exposes_no_implicit_host_tuning_actions():
    assert "optimizations" not in " ".join(TelemtPlugin.meta.capabilities.actions)


def test_update_binary_exposes_public_runtime_action():
    plugin = TelemtPlugin()
    with patch("hydra.plugins.telemt.plugin.installation.update_binary", return_value=True) as update:
        assert plugin.update_binary() is True
    update.assert_called_once()


def test_configure_returns_fragment_with_port():
    """configure() возвращает ConfigFragment с nft_tproxy_ports=[8443]."""
    p = TelemtPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [8443]
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_returns_fragment_even_without_users():
    """Без юзеров configure всё равно возвращает nft_tproxy_ports."""
    p = TelemtPlugin()
    state = _make_state([])
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [8443]


def test_configure_and_client_link_do_not_create_or_mutate_protocol_state():
    plugin = TelemtPlugin()
    state = AppState()
    state.network.server_ip = "1.2.3.4"
    user = _make_user("a@x.com", uuid="uuid-a")
    before = copy.deepcopy(state)

    plugin.configure(state)
    with patch(
        "hydra.plugins.telemt.telemt_ios_fix.status",
        return_value={"enabled": False},
    ):
        plugin.client_link(user, state)

    assert state == before


def test_configure_skips_blocked_users():
    """Заблокированные юзеры не попадают в конфиг."""
    p = TelemtPlugin()
    state = _make_state(
        [
            _make_user("active@x.com", uuid="uuid-a"),
            _make_user("blocked@x.com", uuid="uuid-b", blocked=True),
        ]
    )
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [8443]
    pending = p._pending_cfg
    assert pending is not None
    assert "uuid-b" not in pending
    # в TOML только один пользователь
    user_lines = [line for line in pending.splitlines() if "uuid" in line]
    assert len(user_lines) == 0  # uuid не хранится, хранится username
    secret_lines = [
        line for line in pending.splitlines() if "=" in line and '"' in line and line.strip().startswith('"u')
    ]
    assert len(secret_lines) == 1


def test_client_link_valid_uri():
    """client_link() начинается с tg://proxy."""
    p = TelemtPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    link = p.client_link(_make_user("a@x.com", uuid="uuid-a"), state)

    assert link.startswith("tg://proxy?server=1.2.3.4&port=8443&secret=ee")
    assert link.endswith("google.com".encode().hex())


def test_client_link_with_tls_domain():
    """С доменом secret включает ee prefix + domain hex."""
    p = TelemtPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], domain="example.com")
    link = p.client_link(_make_user("a@x.com", uuid="uuid-a"), state)

    assert link.startswith("tg://proxy?server=1.2.3.4&port=8443&secret=ee")
    # ee + 32 hex secret + domain in hex
    expected_domain_hex = "example.com".encode().hex()
    assert link.endswith(expected_domain_hex)


def test_common_user_lifecycle_updates_rendered_telemt_access():
    plugin = TelemtPlugin()
    state = _make_state()
    rendered: list[str] = []

    def apply_config(current_state):
        plugin.configure(current_state)
        rendered.append(plugin._pending_cfg or "")
        return True

    lifecycle = UserLifecycleOperations(
        transports=lambda: [cast(UserTransport, plugin)],
        apply_config=apply_config,
        save_state=lambda _state: None,
        last_apply_error=lambda: "",
        log_rollback_error=lambda _error: None,
        invoker=PluginInvoker(),
    )
    user = _make_user("a@x.com", uuid="uuid-a")

    with patch.object(UserLifecycleOperations, "_restart_subscriptions"):
        lifecycle.add(state, user)
        lifecycle.block(state, user.email)
        lifecycle.unblock(state, user.email)
        lifecycle.remove(state, user.email)

    assert user.credentials["telemt"]["username"] in rendered[0]
    assert user.credentials["telemt"]["username"] not in rendered[1]
    assert user.credentials["telemt"]["username"] in rendered[2]
    assert user.credentials["telemt"]["username"] not in rendered[3]


def test_on_user_add_sets_credentials():
    """После on_user_add в user.credentials['telemt'] есть username/secret."""
    p = TelemtPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state([user])

    with patch.object(p, "apply", return_value=True):
        p.on_user_add(user, state)

    assert "telemt" in user.credentials
    assert "username" in user.credentials["telemt"]
    assert "secret" in user.credentials["telemt"]
    assert len(user.credentials["telemt"]["secret"]) == 32  # 32 hex


def test_deterministic_creds():
    """Одинаковый uuid → одинаковые креды."""
    p = TelemtPlugin()
    uuid = "same-uuid-123"

    u1 = _make_user("a@x.com", uuid=uuid)
    u2 = _make_user("b@x.com", uuid=uuid)

    uname1 = p._derive_username(u1.uuid)
    uname2 = p._derive_username(u2.uuid)
    assert uname1 == uname2

    sec1 = p._derive_secret(u1.uuid)
    sec2 = p._derive_secret(u2.uuid)
    assert sec1 == sec2


def test_generate_client_config_returns_json_with_link():
    """generate_client_config возвращает JSON с полем link."""
    p = TelemtPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    user = _make_user("a@x.com", uuid="uuid-a")

    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    assert "link" in parsed
    assert parsed["protocol"] == "telemt"
    assert parsed["link"].startswith("tg://proxy")


def test_status_returns_plugin_status():
    """status() возвращает PluginStatus без ошибок."""
    p = TelemtPlugin()
    with (
        patch.object(TelemtPlugin, "_installed", return_value=True),
        patch("hydra.plugins.telemt.plugin.CONFIG_FILE") as mock_cfg,
        patch("subprocess.run") as mock_run,
    ):
        mock_cfg.exists.return_value = True
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.port == 8443


def test_build_toml_basic():
    """_build_toml генерирует валидный TOML."""
    p = TelemtPlugin()
    toml = p._build_toml(
        port=8443,
        ipv4=True,
        ipv6=False,
        tls_domain="mask.example",
        users={"user1": "aabbccdd11223344aabbccdd11223344"},
    )

    assert "port = 8443" in toml
    assert '"user1" = "aabbccdd11223344aabbccdd11223344"' in toml
    assert 'ip = "0.0.0.0"' in toml
    assert 'tls_domain = "mask.example"' in toml
    assert "[access.users]" in toml


def test_build_toml_with_tls_domain():
    """С TLS доменом в секции censorship."""
    p = TelemtPlugin()
    toml = p._build_toml(
        port=8443,
        ipv4=True,
        ipv6=False,
        tls_domain="vpn.example.com",
        users={},
    )

    assert 'tls_domain = "vpn.example.com"' in toml
    assert "mask = true" in toml


def test_build_toml_multiple_users():
    """Несколько пользователей в секции [access.users]."""
    p = TelemtPlugin()
    toml = p._build_toml(
        port=8443,
        ipv4=True,
        ipv6=False,
        tls_domain="mask.example",
        users={"u1": "s1", "u2": "s2", "u3": "s3"},
    )

    assert '"u1" = "s1"' in toml
    assert '"u2" = "s2"' in toml
    assert '"u3" = "s3"' in toml


def test_make_tls_secret():
    """_make_tls_secret формирует корректный ee-секрет."""
    secret = TelemtPlugin._make_tls_secret("aa", "example.com")
    expected = f"eeaa{('example.com').encode().hex()}"
    assert secret == expected
    assert secret.startswith("ee")


def test_generate_client_config_empty_without_ip():
    """Без server_ip возвращается JSON с ссылкой (public_ip fallback)."""
    p = TelemtPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], server_ip="")
    user = _make_user("a@x.com", uuid="uuid-a")
    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    assert "link" in parsed
    # public_ip вернёт 'unknown' через мок, но ссылка всё равно будет
