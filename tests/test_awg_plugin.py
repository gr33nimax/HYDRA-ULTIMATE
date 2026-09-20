"""tests/test_awg_plugin.py — Тесты для AmneziaWG plugin v2."""

import base64
import copy
import json
import struct
import zlib
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.amneziawg.plugin import (
    AWG_CONF,
    AWG_CONF_1,
    AmneziaWGPlugin,
)
from hydra.plugins.amneziawg.constants import (
    DEFAULT_OBFUSCATION,
    ENDPOINT_TAG_DESKTOP,
    ENDPOINT_TAG_MOBILE,
)
from hydra.plugins.amneziawg.presets import generate_params, validate_params
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
        "address_octet": "4" if profile == "mobile" else "3",
    }


def test_plugin_meta():
    p = AmneziaWGPlugin()
    assert p.meta.name == "amneziawg"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_status_uses_persisted_lifecycle_instead_of_config_presence():
    p = AmneziaWGPlugin()
    state = AppState(
        protocols={
            "amneziawg": PluginState(installed=True, enabled=False),
        }
    )

    with patch.object(p, "_installed", return_value=True), patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as config:
        config.exists.return_value = True
        status = p.status(state)

    assert status.installed is True
    assert status.enabled is False
    assert status.running is False


def test_configure_no_side_effects():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    _set_keys(user)
    state = _make_state([user])
    before = copy.deepcopy(state)

    with (
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf,
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1") as mock_conf_1,
        patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run,
    ):
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


def test_on_user_add_defers_apply_to_orchestrator():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        p.on_user_add(user, state)

    host_run.assert_not_called()
    credentials = user.credentials["amneziawg"]
    assert credentials["private_key"] and credentials["public_key"] and credentials["preshared_key"]
    assert credentials["public_key"] != credentials["private_key"]


def test_on_user_remove_defers_apply_to_orchestrator():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run:
        state.users = []
        p.on_user_remove(user, state)

    host_run.assert_not_called()


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
    state = AppState(
        protocols={
            "amneziawg": PluginState(enabled=True, config={}),
            "naive": PluginState(enabled=True, config={"network": "both"}),
            "trusttunnel": PluginState(enabled=True, config={"network": "quic"}),
            "wdtt": PluginState(enabled=True, config={"network": "10.80.0.0/16"}),
        }
    )

    used = p._used_networks(state)

    assert "both" not in used
    assert "quic" not in used
    assert "10.80.0.0/16" in used
    assert p._is_network_free("10.67.67.0/24", used) is True
    assert p._is_network_free("10.80.1.0/24", used) is False


def test_invalid_legacy_amnezia_network_falls_back_without_raising():
    p = AmneziaWGPlugin()
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={"profiles": {"desktop": {"network": "both"}}},
            ),
            "naive": PluginState(enabled=True, config={"network": "both"}),
        }
    )
    result = p._network_for_profile(state, "desktop", "10.67.67.0/24")

    assert result == ("10.67.67", "1", "10.67.67.0/24")


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

    with (
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf),
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile_conf),
        patch.object(p, "_generate_private_key", return_value="mobile-server"),
        patch.object(
            p,
            "_generate_keys",
            return_value={
                "private_key": "mobile-private",
                "public_key": "mobile-public",
                "preshared_key": "mobile-psk",
                "address_octet": "4",
                "address_octet": "4",
            },
        ),
        patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run,
    ):
        assert p.add_profile("mobile", "mobile:tele2", state) is True

    host_run.assert_not_called()
    assert desktop_conf.read_bytes() == original_file
    assert not mobile_conf.exists()
    profiles = state.protocols["amneziawg"].config["profiles"]
    assert isinstance(profiles, dict)
    desktop_profile = profiles.get("desktop")
    mobile_profile = profiles.get("mobile")
    assert isinstance(desktop_profile, dict)
    assert isinstance(mobile_profile, dict)
    for profile in (desktop_profile, mobile_profile):
        assert isinstance(profile["server_private_key"], str)
        assert profile["server_private_key"]
    assert user.credentials["amneziawg_mobile"]["public_key"] == "mobile-public"
    assert "amneziawg_mobile" not in blocked.credentials


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
                            "interface": ENDPOINT_TAG_DESKTOP,
                            "port": 51820,
                            "network": "10.67.67.0/24",
                            "server_private_key": "server",
                            "preset": "wired",
                            "obfuscation": dict(DEFAULT_OBFUSCATION),
                        },
                    },
                },
            ),
        },
    )
    original_file = desktop_conf.read_bytes()
    replacement = {"Jc": "7", "I1": ""}

    with (
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop_conf),
        patch.object(p, "_generate_obfuscation", return_value=replacement),
        patch("hydra.plugins.amneziawg.plugin.HOST.run") as host_run,
    ):
        assert (
            p.rotate_obfuscation(
                state,
                profile="desktop",
                preset="stealth",
            )
            is True
        )

    host_run.assert_not_called()
    assert desktop_conf.read_bytes() == original_file
    profiles = state.protocols["amneziawg"].config["profiles"]
    assert isinstance(profiles, dict)
    desktop = profiles.get("desktop")
    assert isinstance(desktop, dict)
    assert desktop["preset"] == "stealth"
    assert desktop["obfuscation"] == replacement


# The padding each packet type carries must fit one header-protection nonce (12 bytes); above
# that minimum upstream lets each field keep its own value. These bounds are the legacy preset
# ranges with only a lower bound of 12 applied, so a zero-only field becomes the minimum and a
# wider field keeps its headroom.
AWG3_S_BOUNDS = {
    "wired": ((20, 120), (20, 120), (12, 12), (12, 12)),
    "mobile": ((15, 80), (15, 80), (12, 12), (12, 12)),
    "stealth": ((50, 150), (50, 150), (12, 55), (12, 24)),
    "low_latency": ((12, 15), (12, 15), (12, 12), (12, 12)),
}


def _awg_params(s1, s2, s3, s4) -> dict:
    """A complete, otherwise-valid parameter set with the four paddings under test."""
    return {
        "Jc": "4",
        "Jmin": "50",
        "Jmax": "150",
        "S1": str(s1),
        "S2": str(s2),
        "S3": str(s3),
        "S4": str(s4),
        "H1": "10001",
        "H2": "10002",
        "H3": "10003",
        "H4": "10004",
    }


def test_3x_paddings_keep_their_own_range_above_the_nonce_minimum():
    # Forcing all four fields to one value rewrites a working server profile: 3.x needs each
    # padding at least as large as the header-protection nonce, and nothing more. A field whose
    # legacy range cannot reach the minimum is the only one that gets lifted.
    for mode in ("3.0", "3.1"):
        for strategy, bounds in AWG3_S_BOUNDS.items():
            params = generate_params(strategy=strategy, seed=7, protocol_mode=mode)
            drawn = [int(params[f"S{i}"]) for i in range(1, 5)]
            for index, (field, (low, high)) in enumerate(zip(("S1", "S2", "S3", "S4"), bounds)):
                assert low <= drawn[index] <= high, (mode, strategy, field, params[field])
            assert drawn != [32, 32, 32, 32], f"{mode}/{strategy} is still forced to a constant"
            ok, reason = validate_params(params, protocol_mode=mode)
            assert ok, reason
            assert "RandomTrailers" not in params, mode
            assert "DisableCookies" not in params, mode


def test_3x_lifts_a_zero_only_field_to_the_nonce_minimum():
    # wired, mobile and low_latency draw S3=S4=0 for 2.0, which the 3.x protocol cannot carry.
    for strategy in ("wired", "mobile", "low_latency"):
        params = generate_params(strategy=strategy, seed=7, protocol_mode="3.1")
        assert params["S3"] == "12", (strategy, params["S3"])
        assert params["S4"] == "12", (strategy, params["S4"])


def test_3x_keeps_the_s1_s2_fingerprint_guard():
    for mode in ("3.0", "3.1"):
        for strategy in AWG3_S_BOUNDS:
            params = generate_params(strategy=strategy, seed=11, protocol_mode=mode)
            assert int(params["S1"]) + 56 != int(params["S2"]), (mode, strategy)


def test_3x_accepts_unequal_server_paddings():
    # A live server met 62/86/45/21 and dropped cookie packets for an unrelated reason; the values
    # themselves are valid for 3.x and must pass, not be rewritten.
    for mode in ("3.0", "3.1"):
        ok, reason = validate_params(_awg_params(62, 86, 45, 21), protocol_mode=mode)
        assert ok, reason
    ok, reason = validate_params(_awg_params(32, 32, 32, 32), protocol_mode="3.1")
    assert ok, reason


def test_3x_refuses_a_padding_below_the_nonce_minimum_without_substituting():
    cases = {
        "S1": (11, 86, 45, 21),
        "S2": (62, 11, 45, 21),
        "S3": (62, 86, 11, 21),
        "S4": (62, 86, 45, 11),
    }
    for field, values in cases.items():
        for mode in ("3.0", "3.1"):
            ok, reason = validate_params(_awg_params(*values), protocol_mode=mode)
            assert not ok, (field, mode)
            assert field in reason, (field, reason)
            assert "12" in reason, (field, reason)


def test_2x_paddings_are_untouched_by_the_3x_minimum():
    # 2.0 carries no header protection, so a small or zero padding stays legal there and the
    # generation path must not clamp it: a seeded 2.0 set is stable and low_latency still draws
    # its two zero fields.
    for strategy in AWG3_S_BOUNDS:
        twice = [generate_params(strategy=strategy, seed=7, protocol_mode="2.0") for _ in range(2)]
        assert twice[0] == twice[1], strategy
    low_latency = generate_params(strategy="low_latency", seed=7, protocol_mode="2.0")
    assert (low_latency["S3"], low_latency["S4"]) == ("0", "0")
    assert low_latency == generate_params(strategy="low_latency", seed=7), "the default mode is 2.0"
    for mode in ("", "2.0"):
        ok, reason = validate_params(_awg_params(62, 86, 30, 11), protocol_mode=mode)
        assert ok, (mode, reason)


def test_on_user_add_assigns_an_address_and_projects_the_new_peer():
    plugin = AmneziaWGPlugin()
    existing = _make_user("existing@example.com", uuid="existing")
    _set_keys(existing)
    state = AppState(
        protocols={"amneziawg": PluginState(enabled=True, config={})},
        users=[existing],
    )
    plugin.on_enable(state)
    new_user = _make_user("new@example.com", uuid="new")
    state.users.append(new_user)

    plugin.on_user_add(new_user, state)

    assert new_user.credentials["amneziawg"]["address_octet"]
    assert plugin.generate_client_config(new_user, state)
    peers = plugin.server_endpoints(state)[0]["peers"]
    assert any(peer["public_key"] == new_user.credentials["amneziawg"]["public_key"] for peer in peers)
    assert existing.credentials["amneziawg"]["address_octet"] == "3"


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
            "address_octet": "3",
        },
        {
            "private_key": "mobile-private",
            "public_key": "mobile-public",
            "preshared_key": "mobile-psk",
            "address_octet": "4",
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
                            "interface": ENDPOINT_TAG_DESKTOP,
                            "port": "51820",
                            "network": "10.67.67.0/24",
                            "preset": "wired",
                            "obfuscation": dict(DEFAULT_OBFUSCATION),
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


def test_issued_profiles_exclude_an_unissued_mobile_draft_without_mutation():
    plugin = AmneziaWGPlugin()
    user = _make_user("active@example.com")
    _set_keys(user, "desktop")
    user.credentials["amneziawg_mobile"] = {
        "private_key": "mobile-private",
        "public_key": "mobile-public",
        "preshared_key": "mobile-psk",
    }
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "profiles": {
                        "desktop": {"server_private_key": "desktop-server"},
                        "mobile": {"server_private_key": "mobile-server"},
                    },
                },
            ),
        },
        users=[user],
    )
    before = copy.deepcopy(state)

    assert [profile["name"] for profile in plugin.get_profiles(state)] == ["desktop", "mobile"]
    assert [profile["name"] for profile in plugin.get_issued_profiles(state)] == ["desktop"]
    assert state == before


def test_presets_strategies_and_overrides():
    from hydra.plugins.amneziawg.presets import (
        generate_params,
        validate_params,
        STRATEGIES,
        CARRIER_OVERRIDES,
        LEGACY_PRESET_MAP,
        list_presets,
        list_strategies,
        list_carriers,
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
