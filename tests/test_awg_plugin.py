"""tests/test_awg_plugin.py — Тесты для AmneziaWG plugin v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
import time
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin, AWG_CONF, AWG_INTERFACE
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState, User


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
         patch("hydra.core.state.load_state", return_value=state), \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as config:
        config.exists.return_value = True
        status = p.status()

    assert status.installed is True
    assert status.enabled is False
    assert status.running is False


def test_configure_returns_tproxy_ifaces():
    p = AmneziaWGPlugin()
    state = _make_state([_make_user("a@x.com")])

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
    state = _make_state([_make_user("a@x.com")])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1") as mock_conf_1, \
         patch.object(p, "_awg") as mock_awg:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_conf_1.exists.return_value = False
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        p.configure(state)
        mock_conf.write_text.assert_not_called()


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
        net = p._resolve_network(state)
        assert net == "10.67.67.0/24"
        assert state.protocols["amneziawg"].config["network"] == "10.67.67.0/24"

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


def test_profile_network_rejects_installer_reserved_subnet():
    p = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(enabled=True, config={})})
    conf = MagicMock()
    conf.exists.return_value = True
    conf.read_text.return_value = "[Interface]\nAddress = 10.66.66.1/24\n"

    base, server_octet, network = p._network_for_profile(
        state, conf, "desktop", "10.67.67.0/24",
    )

    assert (base, server_octet, network) == ("10.67.67", "1", "10.67.67.0/24")


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

