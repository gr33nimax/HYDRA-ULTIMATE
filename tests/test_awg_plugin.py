"""tests/test_awg_plugin.py — Тесты для AmneziaWG plugin v2."""
import copy
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
import time
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.amneziawg.plugin import (
    AWG_CONF,
    AWG_CONF_1,
    AWG_INTERFACE,
    AWG_INTERFACE_1,
    AWG_UNIT,
    AWG_UNIT_1,
    AmneziaWGPlugin,
)
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState, User
from hydra.services.plugin_commands import PluginCommandService


FAKE_CONF = """[Interface]
PrivateKey = sFk7RkMx9J0XJ7WpP8mF0Q==
Address = 10.66.66.1/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 8
S2 = 72
MTU = 1420
"""


def _make_state(users: list | None = None) -> AppState:
    state = AppState()
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def _set_keys(user: User, profile: str = "desktop", suffix: str = "d") -> None:
    key = "amneziawg" if profile == "desktop" else f"amneziawg_{profile}"
    user.credentials[key] = {
        "private_key": f"private-{suffix}",
        "public_key": f"public-{suffix}",
        "preshared_key": f"psk-{suffix}",
    }


def test_plugin_meta():
    p = AmneziaWGPlugin()
    assert p.meta.name == "amneziawg"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_kernel_module_reports_reboot_when_dkms_targets_newer_kernel():
    p = AmneziaWGPlugin()

    def run(command, **kwargs):
        if command == ["lsmod"]:
            return MagicMock(returncode=0, stdout="")
        if command == ["modprobe", "amneziawg"]:
            return MagicMock(returncode=1, stdout="", stderr="module not found")
        if command == ["dkms", "status"]:
            return MagicMock(
                returncode=0,
                stdout="amneziawg/1.0.0, 6.12.96+deb13-amd64, x86_64: installed\n",
            )
        raise AssertionError(command)

    with patch("hydra.plugins.amneziawg.plugin.HOST.run", side_effect=run), \
         patch("hydra.plugins.amneziawg.plugin.HOST.which", return_value="/usr/sbin/dkms"), \
         patch("platform.release", return_value="6.12.88+deb13-amd64"):
        ready, detail = p._ensure_kernel_module()

    assert ready is False
    assert "6.12.96+deb13-amd64" in detail
    assert "6.12.88+deb13-amd64" in detail
    assert "Перезагрузите" in detail


def test_status_uses_persisted_lifecycle_instead_of_config_presence():
    p = AmneziaWGPlugin()
    state = AppState(protocols={
        "amneziawg": PluginState(installed=True, enabled=False),
    })

    with patch.object(p, "_installed", return_value=True), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as config:
        config.exists.return_value = True
        status = p.status(state)

    assert status.installed is True
    assert status.enabled is False
    assert status.running is False


def test_configure_returns_tproxy_ifaces():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    _set_keys(user)
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1") as mock_conf_1, \
         patch.object(p, "_awg") as mock_awg:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_conf_1.exists.return_value = False
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        frag = p.configure(state)

        assert isinstance(frag, ConfigFragment)
        assert frag.nft_tproxy_ifaces == [AWG_INTERFACE]
        assert frag.route_rules == []
        assert frag.nft_tproxy_ports == []
        assert frag.inbounds == []
        assert frag.outbounds == []


def test_configure_no_side_effects():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    _set_keys(user)
    state = _make_state([user])
    before = copy.deepcopy(state)

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1") as mock_conf_1, \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_conf_1.exists.return_value = False

        p.configure(state)
        mock_conf.write_text.assert_not_called()
        mock_conf_1.write_text.assert_not_called()
        host_run.assert_not_called()
        assert state == before


def test_configure_empty_when_no_conf():
    p = AmneziaWGPlugin()
    state = _make_state([_make_user("a@x.com")])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = False

        frag = p.configure(state)
        assert frag.route_rules == []
        assert frag.inbounds == []


def test_traffic_uses_state():
    p = AmneziaWGPlugin()
    user_a = _make_user("a@x.com", uuid="uuid-a")
    user_a.credentials["amneziawg"] = {"public_key": "pub_a"}
    state = _make_state([user_a])

    with patch.object(p, "_installed", return_value=True), \
         patch.object(p, "_is_up", return_value=True), \
         patch.object(p, "_awg") as mock_awg:
        def fake_awg(*args, _input="", **kw):
            if args[0] == "pubkey" and _input:
                return MagicMock(stdout="pub_a\n", returncode=0)
            if args[:2] == ("show", AWG_INTERFACE) and args[2] == "transfer":
                return MagicMock(stdout="pub_a\t1000\t500\npub_unknown\t200\t100\n", returncode=0)
            return MagicMock(stdout="", returncode=1)
        mock_awg.side_effect = fake_awg

        result = p.traffic(state)
        assert result.get("a@x.com") == 1500
        assert "?" not in result


def test_on_user_add_defers_apply_to_orchestrator():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg, \
         patch.object(p, "_is_up", return_value=True), \
         patch("hydra.plugins.amneziawg.plugin.subprocess.run") as mock_run:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)
        mock_run.return_value = MagicMock(returncode=0)

        p.on_user_add(user, state)
        mock_conf.write_text.assert_not_called()


def test_on_user_remove_defers_apply_to_orchestrator():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg, \
         patch.object(p, "_is_up", return_value=True):
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        state.users = []
        p.on_user_remove(user, state)
        mock_conf.write_text.assert_not_called()


def test_connected_clients_returns_list():
    p = AmneziaWGPlugin()
    with patch.object(p, "_installed", return_value=True), \
         patch.object(p, "_is_up", return_value=True), \
         patch.object(p, "_awg") as mock_awg:
        handshake = int(time.time()) - 30
        mock_awg.return_value = MagicMock(
            stdout=f"interface\tpriv\tpub\t1234\npub_key\tendpoint\t:51820\t10.66.66.2/32\t{handshake}\t500\t200\t1234\n",
            returncode=0,
        )
        p._peer_map = {"pub_key": "a@x.com"}
        clients = p.connected_clients()
        assert len(clients) >= 1
        assert clients[0]["email"] == "a@x.com"


def test_connected_clients_hides_stale_peers_and_groups_profiles():
    p = AmneziaWGPlugin()
    now = int(time.time())
    dumps = {
        "awg0": f"header\npub_d\tpsk\t1.2.3.4:1\t10.0.0.2/32\t{now - 20}\t500\t200\t0\n",
        "awg1": f"header\npub_m\tpsk\t1.2.3.4:2\t10.0.1.2/32\t{now - 40}\t300\t100\t0\n"
                f"pub_old\tpsk\t1.2.3.5:1\t10.0.1.3/32\t{now - 9999}\t999\t999\t0\n",
    }

    def awg(*args):
        return MagicMock(returncode=0, stdout=dumps[args[1]])

    state = AppState(users=[User(
        email="same@example.com", uuid="u1", credentials={
            "amneziawg": {"public_key": "pub_d"},
            "amneziawg_mobile": {"public_key": "pub_m"},
        },
    )])
    with patch.object(p, "_installed", return_value=True), \
         patch.object(p, "_is_up_iface", return_value=True), \
         patch.object(p, "_awg", side_effect=awg):
        clients = p.connected_clients(state)

    assert len(clients) == 1
    assert clients[0]["email"] == "same@example.com"
    assert set(clients[0]["profiles"]) == {"Desktop", "Mobile"}
    assert clients[0]["rx"] == 800
    assert clients[0]["tx"] == 300
def test_resolve_network_avoids_conflicts():
    from hydra.core.state import PluginState
    p = AmneziaWGPlugin()
    state = _make_state()
    # Эмулируем конфликт: WDTT занял 10.66.66.0/16
    state.protocols["wdtt"] = PluginState(enabled=True, config={"network": "10.66.66.0/16"})
    state.protocols["amneziawg"] = PluginState(enabled=True, config={})

    # Если awg0.conf не существует, должен выбрать первую свободную сеть (10.67.67.0/24)
    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = False
        before = copy.deepcopy(state)
        net = p._resolve_network(state)
        assert net == "10.67.67.0/24"
        assert state == before

    # Если в awg0.conf прописана конфликтующая сеть (10.66.66.1/24), он должен проигнорировать её и выбрать свободную (10.67.67.0/24)
    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = "Address = 10.66.66.1/24"
        # Сбрасываем старую сохраненную сеть
        state.protocols["amneziawg"].config = {}
        net = p._resolve_network(state)
        assert net == "10.67.67.0/24"


def test_network_discovery_ignores_transport_modes_from_other_plugins():
    p = AmneziaWGPlugin()
    state = AppState(protocols={
        "amneziawg": PluginState(enabled=True, config={}),
        "naive": PluginState(enabled=True, config={"network": "both"}),
        "trusttunnel": PluginState(enabled=True, config={"network": "quic"}),
        "wdtt": PluginState(enabled=True, config={"network": "10.80.0.0/16"}),
    })

    used = p._used_networks(state)

    assert "both" not in used
    assert "quic" not in used
    assert "10.80.0.0/16" in used
    assert p._is_network_free("10.67.67.0/24", used) is True
    assert p._is_network_free("10.80.1.0/24", used) is False


def test_invalid_legacy_amnezia_network_falls_back_without_raising():
    p = AmneziaWGPlugin()
    state = AppState(protocols={
        "amneziawg": PluginState(
            enabled=True,
            config={"profiles": {"desktop": {"network": "both"}}},
        ),
        "naive": PluginState(enabled=True, config={"network": "both"}),
    })
    conf = MagicMock()
    conf.exists.return_value = False

    result = p._network_for_profile(state, conf, "desktop", "10.67.67.0/24")

    assert result == ("10.67.67", "1", "10.67.67.0/24")


def test_desired_profile_network_overlays_existing_runtime_network():
    p = AmneziaWGPlugin()
    state = AppState(protocols={
        "amneziawg": PluginState(
            enabled=True,
            config={"profiles": {"desktop": {"network": "10.67.67.0/24"}}},
        ),
        "wdtt": PluginState(enabled=True, config={"network": "10.66.66.0/16"}),
    })
    conf = MagicMock()
    conf.exists.return_value = True
    conf.read_text.return_value = "[Interface]\nAddress = 10.66.66.1/24\n"

    base, server_octet, network = p._network_for_profile(
        state, conf, "desktop", "10.67.67.0/24",
    )

    assert (base, server_octet, network) == ("10.67.67", "1", "10.67.67.0/24")


def test_configure_reconciles_existing_interface_to_desired_network(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    desktop_conf.write_text(FAKE_CONF, encoding="utf-8")
    mobile_conf = tmp_path / "awg1.conf"
    state = AppState(protocols={
        "amneziawg": PluginState(
            enabled=True,
            config={"profiles": {"desktop": {"network": "10.67.67.0/24"}}},
        ),
        "wdtt": PluginState(enabled=True, config={"network": "10.66.66.0/16"}),
    })

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf):
        p.configure(state)

    assert "Address = 10.67.67.1/24" in p._pending_conf
    assert "Address = 10.66.66.1/24" not in p._pending_conf


def test_mobile_config_is_rendered_from_state_without_existing_file(tmp_path):
    p = AmneziaWGPlugin()
    user = _make_user("mobile@example.com")
    _set_keys(user, "desktop", "d")
    _set_keys(user, "mobile", "m")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server-desktop",
                            "obfuscation": {"Jc": "4"},
                        },
                        "mobile": {
                            "interface": AWG_INTERFACE_1,
                            "port": 51999,
                            "network": "10.88.0.0/24",
                            "server_private_key": "server-mobile",
                            "obfuscation": {"Jc": "3", "I1": "mobile.example"},
                            "mtu": 1280,
                        },
                    },
                },
            ),
        },
        users=[user],
    )
    desktop_conf = tmp_path / "awg0.conf"
    mobile_conf = tmp_path / "awg1.conf"
    before = copy.deepcopy(state)

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        fragment = p.configure(state)

    assert state == before
    host_run.assert_not_called()
    assert fragment.nft_tproxy_ifaces == [AWG_INTERFACE, AWG_INTERFACE_1]
    assert p._pending_conf_1 is not None
    assert "PrivateKey = server-mobile" in p._pending_conf_1
    assert "Address = 10.88.0.1/24" in p._pending_conf_1
    assert "ListenPort = 51999" in p._pending_conf_1
    assert "PublicKey = public-m" in p._pending_conf_1
    assert not mobile_conf.exists()


def test_desired_profile_overlays_existing_interface_fields(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    desktop_conf.write_text(
        """[Interface]
PrivateKey = old-key
Address = 10.1.1.9/24
ListenPort = 1111
Jc = 9
I1 = stale.example
MTU = 1400
""",
        encoding="utf-8",
    )
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 52222,
                            "network": "10.77.0.0/24",
                            "server_private_key": "desired-key",
                            "obfuscation": {"Jc": "3", "H1": "123"},
                            "mtu": 1337,
                        },
                    },
                },
            ),
        },
    )

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", tmp_path / "awg1.conf"):
        p.configure(state)

    rendered = p._pending_conf or ""
    assert "PrivateKey = desired-key" in rendered
    assert "Address = 10.77.0.1/24" in rendered
    assert "ListenPort = 52222" in rendered
    assert "MTU = 1337" in rendered
    assert "Jc = 3" in rendered
    assert "H1 = 123" in rendered
    assert "old-key" not in rendered
    assert "stale.example" not in rendered


def test_add_profile_only_mutates_desired_state(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    desktop_conf.write_text(FAKE_CONF, encoding="utf-8")
    mobile_conf = tmp_path / "awg1.conf"
    user = _make_user("active@example.com")
    _set_keys(user, "desktop", "d")
    blocked = _make_user("blocked@example.com", uuid="u2", blocked=True)
    state = AppState(
        protocols={"amneziawg": PluginState(enabled=True, config={})},
        users=[user, blocked],
    )
    original_file = desktop_conf.read_bytes()

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf), \
         patch.object(p, "_generate_private_key", return_value="mobile-server"), \
             patch.object(
                 p,
                 "_generate_keys",
             return_value={
                 "private_key": "mobile-private",
                 "public_key": "mobile-public",
                 "preshared_key": "mobile-psk",
             },
         ), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        assert p.add_profile("mobile", "mobile:tele2", state) is True

    host_run.assert_not_called()
    assert desktop_conf.read_bytes() == original_file
    assert not mobile_conf.exists()
    profiles = state.protocols["amneziawg"].config["profiles"]
    assert profiles["desktop"]["server_private_key"] == "sFk7RkMx9J0XJ7WpP8mF0Q=="
    assert profiles["mobile"]["server_private_key"] == "mobile-server"
    assert user.credentials["amneziawg_mobile"]["public_key"] == "mobile-public"
    assert "amneziawg_mobile" not in blocked.credentials


def test_add_profile_rolls_back_with_application_transaction(tmp_path):
    p = AmneziaWGPlugin()
    user = _make_user("rollback@example.com")
    _set_keys(user, "desktop", "d")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server-desktop",
                            "obfuscation": {"Jc": "4"},
                        },
                    },
                },
            ),
        },
        users=[user],
    )
    before = copy.deepcopy(state)
    saved: list[AppState] = []
    service = PluginCommandService(
        get_plugin=lambda name: p if name == "amneziawg" else None,
        apply_config=lambda current: False,
        save_state=lambda current: saved.append(copy.deepcopy(current)),
    )

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", tmp_path / "awg0.conf"), \
         patch.object(p, "_generate_private_key", return_value="mobile-server"), \
         patch.object(
             p,
             "_generate_keys",
             return_value={
                 "private_key": "mobile-private",
                 "public_key": "mobile-public",
                 "preshared_key": "mobile-psk",
             },
         ), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        host_run.return_value.returncode = 0
        assert service.execute(
            state,
            "amneziawg",
            "add_profile",
            name="mobile",
            preset="mobile:generic",
        ) is False

    assert [item.args[0] for item in host_run.call_args_list] == [
        ["systemctl", "stop", AWG_UNIT],
        ["systemctl", "stop", AWG_UNIT_1],
    ]
    assert state == before
    assert saved[-1] == before


def test_remove_profile_defers_runtime_cleanup_to_apply(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    mobile_conf = tmp_path / "awg1.conf"
    mobile_conf.write_text("mobile-runtime", encoding="utf-8")
    user = _make_user("active@example.com")
    _set_keys(user, "desktop", "d")
    _set_keys(user, "mobile", "m")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server-desktop",
                            "obfuscation": {},
                        },
                        "mobile": {
                            "interface": AWG_INTERFACE_1,
                            "port": 51821,
                            "network": "10.68.68.0/24",
                            "server_private_key": "server-mobile",
                            "obfuscation": {},
                        },
                    },
                },
            ),
        },
        users=[user],
    )

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        assert p.remove_profile("mobile", state) is True
        host_run.assert_not_called()
        assert mobile_conf.read_text(encoding="utf-8") == "mobile-runtime"

        p.configure(state)
        with patch.object(p, "_apply_iface", return_value=True):
            assert p.apply(state) is True

    assert not mobile_conf.exists()
    assert "mobile" not in state.protocols["amneziawg"].config["profiles"]
    assert "amneziawg_mobile" not in user.credentials
    host_run.assert_any_call(
        ["systemctl", "stop", AWG_UNIT_1],
        capture_output=True,
    )
    host_run.assert_any_call(
        ["systemctl", "disable", AWG_UNIT_1],
        capture_output=True,
    )


def test_rotate_obfuscation_only_mutates_desired_state(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    desktop_conf.write_text(FAKE_CONF, encoding="utf-8")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server",
                            "preset": "wired",
                            "obfuscation": {"Jc": "4"},
                        },
                    },
                },
            ),
        },
    )
    original_file = desktop_conf.read_bytes()
    replacement = {"Jc": "7", "I1": ""}

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch.object(p, "_generate_obfuscation", return_value=replacement), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        assert p.rotate_obfuscation(
            state,
            profile="desktop",
            preset="stealth",
        ) is True

    host_run.assert_not_called()
    assert desktop_conf.read_bytes() == original_file
    desktop = state.protocols["amneziawg"].config["profiles"]["desktop"]
    assert desktop["preset"] == "stealth"
    assert desktop["obfuscation"] == replacement


def test_apply_writes_both_desired_profiles_after_configure(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    mobile_conf = tmp_path / "awg1.conf"
    user = _make_user("both@example.com")
    _set_keys(user, "desktop", "d")
    _set_keys(user, "mobile", "m")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server-d",
                            "obfuscation": {"Jc": "4"},
                        },
                        "mobile": {
                            "interface": AWG_INTERFACE_1,
                            "port": 51821,
                            "network": "10.68.68.0/24",
                            "server_private_key": "server-m",
                            "obfuscation": {"Jc": "3"},
                        },
                    },
                },
            ),
        },
        users=[user],
    )

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf), \
         patch.object(p, "_apply_iface", return_value=True) as apply_iface:
        p.configure(state)
        assert p.apply(state) is True

    assert "PrivateKey = server-d" in desktop_conf.read_text(encoding="utf-8")
    assert "PrivateKey = server-m" in mobile_conf.read_text(encoding="utf-8")
    assert apply_iface.call_count == 2


def test_client_config_and_amnezia_link_are_read_only(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    user = _make_user("reader@example.com")
    _set_keys(user, "desktop", "d")
    desktop_conf.write_text(
        f"""{FAKE_CONF}
### reader@example.com
[Peer]
PublicKey = public-d
PresharedKey = psk-d
AllowedIPs = 10.66.66.2/32
""",
        encoding="utf-8",
    )
    state = AppState(
        protocols={"dnscrypt": PluginState(enabled=True)},
        users=[user],
    )
    state.network.server_ip = "203.0.113.10"
    before_state = copy.deepcopy(state)
    before_file = desktop_conf.read_bytes()

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch.object(p, "_server_pubkey_for_conf", return_value="server-public"), \
         patch.object(p, "_current_port", return_value=51820), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        config = p.generate_client_config(user, state)
        link = p.amnezia_link(user, state)

    host_run.assert_not_called()
    assert "PrivateKey = private-d" in config
    assert "DNS = 203.0.113.10" in config
    assert link.startswith("vpn://")
    assert state == before_state
    assert desktop_conf.read_bytes() == before_file


def test_on_user_add_provisions_active_profiles_only_in_lifecycle():
    p = AmneziaWGPlugin()
    user = _make_user("new@example.com")
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {},
                        "mobile": {},
                    },
                },
            ),
        },
        users=[user],
    )
    generated = [
        {
            "private_key": "desktop-private",
            "public_key": "desktop-public",
            "preshared_key": "desktop-psk",
        },
        {
            "private_key": "mobile-private",
            "public_key": "mobile-public",
            "preshared_key": "mobile-psk",
        },
    ]

    with patch.object(p, "_generate_keys", side_effect=generated):
        p.on_user_add(user, state)

    assert user.credentials["amneziawg"]["public_key"] == "desktop-public"
    assert user.credentials["amneziawg_mobile"]["public_key"] == "mobile-public"


def test_get_profiles_reads_desired_state_without_host_or_mutation():
    p = AmneziaWGPlugin()
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {
                            "interface": AWG_INTERFACE,
                            "port": "51820",
                            "network": "10.67.67.0/24",
                            "preset": "wired",
                            "obfuscation": {"Jc": "4"},
                        },
                    },
                },
            ),
        },
    )
    before = copy.deepcopy(state)

    with patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        profiles = p.get_profiles(state)

    host_run.assert_not_called()
    assert profiles[0]["port"] == 51820
    assert profiles[0]["network"] == "10.67.67.0/24"
    assert state == before


def test_configure_rejects_unprovisioned_user_without_mutating_state(tmp_path):
    p = AmneziaWGPlugin()
    desktop_conf = tmp_path / "awg0.conf"
    desktop_conf.write_text(FAKE_CONF, encoding="utf-8")
    state = AppState(users=[_make_user("missing@example.com")])
    before = copy.deepcopy(state)

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", tmp_path / "awg1.conf"), \
         patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        try:
            p.configure(state)
        except RuntimeError as exc:
            assert "were not provisioned" in str(exc)
        else:
            raise AssertionError("configure accepted missing credentials")

    host_run.assert_not_called()
    assert state == before


def test_presets_strategies_and_overrides():
    from hydra.plugins.amneziawg.presets import (
        generate_params, validate_params, STRATEGIES, CARRIER_OVERRIDES, LEGACY_PRESET_MAP, list_presets, list_strategies, list_carriers
    )
    
    # 1. Test list functions
    assert len(list_presets()) > 0
    assert len(list_strategies()) == 4
    assert len(list_carriers("mobile")) > 1

    # 2. Test generating all strategies
    for strategy in STRATEGIES.keys():
        params = generate_params(strategy=strategy)
        assert params["Jc"].isdigit()
        assert params["Jmin"].isdigit()
        assert params["Jmax"].isdigit()
        assert params["S1"].isdigit()
        assert params["S2"].isdigit()
        assert params["S3"].isdigit()
        assert params["S4"].isdigit()
        assert params["H1"].isdigit()
        assert params["H2"].isdigit()
        assert params["H3"].isdigit()
        assert params["H4"].isdigit()
        
        # Verify validate_params accepts it
        ok, err = validate_params(params)
        assert ok, f"Validation failed for strategy {strategy}: {err}"

    # 3. Test carrier overrides
    for carrier in CARRIER_OVERRIDES.keys():
        params = generate_params(strategy="mobile", carrier=carrier)
        ok, err = validate_params(params)
        assert ok, f"Validation failed for carrier {carrier}: {err}"
        
        # Specific carrier checks
        if carrier == "tele2":
            assert params["Jc"] == "3"
        elif carrier == "megafon":
            assert params["I1"] == ""
        elif carrier == "yota":
            assert int(params["Jmax"]) <= 300

    # 4. Test fingerprint constraint S1 + 56 != S2
    for _ in range(50):
        params = generate_params(strategy="stealth")
        s1 = int(params["S1"])
        s2 = int(params["S2"])
        assert s1 + 56 != s2, f"Fingerprint constraint violated: S1={s1}, S2={s2}"

    # 5. Test uniqueness of H1-H4 and non-default values
    params = generate_params(strategy="wired")
    h1 = int(params["H1"])
    h2 = int(params["H2"])
    h3 = int(params["H3"])
    h4 = int(params["H4"])
    assert len({h1, h2, h3, h4}) == 4
    assert not {h1, h2, h3, h4}.intersection({1, 2, 3, 4})

    # 6. Test seed reproducibility
    p1 = generate_params(strategy="wired", carrier="tele2", seed=42)
    p2 = generate_params(strategy="wired", carrier="tele2", seed=42)
    p3 = generate_params(strategy="wired", carrier="tele2", seed=43)
    assert p1 == p2
    assert p1 != p3

    # 7. Test legacy mappings
    for legacy, (strat, carr) in LEGACY_PRESET_MAP.items():
        p_legacy = generate_params(strategy=legacy, seed=123)
        p_new = generate_params(strategy=strat, carrier=carr, seed=123)
        assert p_legacy == p_new

