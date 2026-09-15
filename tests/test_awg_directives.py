from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.amneziawg import (
    AwgDirectiveError,
    AwgInterfaceDirectives,
    canonical_mode,
)
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin


AWG3 = """[Interface]
PrivateKey = server-private
Address = 10.67.67.1/24
HeaderProtectionKey = header-secret
ContentPaddingAddition = 24
RekeyAfterTime = 120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
Jc = 5
FutureUpstreamSetting = retained

[Peer]
PublicKey = peer
"""


def test_canonical_mode_accepts_only_persisted_values_and_legacy_statuses():
    assert canonical_mode("2.0") == "2.0"
    assert canonical_mode("3.1") == "3.1"
    assert canonical_mode("2", from_upstream=True) == "2.0"
    assert canonical_mode("3", from_upstream=True) == "3.0"

    with pytest.raises(AwgDirectiveError, match="unsupported"):
        canonical_mode("3")


def test_awg3_requires_complete_generation_directives():
    directives = AwgInterfaceDirectives.parse(AWG3)

    assert directives.for_mode("3.0").values["HeaderProtectionKey"] == "header-secret"

    with pytest.raises(AwgDirectiveError, match="RandomTrailers"):
        directives.for_mode("3.1")


def test_mode_two_rejects_generation_directives_and_duplicate_directives():
    directives = AwgInterfaceDirectives.parse(AWG3)
    with pytest.raises(AwgDirectiveError, match="not allowed"):
        directives.for_mode("2.0")

    with pytest.raises(AwgDirectiveError, match="duplicate"):
        AwgInterfaceDirectives.parse("[Interface]\nJc = 1\nJc = 2\n")


def test_a_config_may_carry_several_wg_quick_hooks():
    # Upstream's installer writes several PostUp/PostDown lines: a repeat is how wg-quick is told to
    # run several commands, not a malformed configuration. Rejecting the repeat made an existing
    # server's AWG config unreadable, and its update stopped exactly there.
    parsed = AwgInterfaceDirectives.parse(
        "[Interface]\n"
        "PrivateKey = server-private\n"
        "Address = 10.67.67.1/24\n"
        "PostUp = iptables -I FORWARD -i %i -j ACCEPT\n"
        "PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT\n"
        "\n[Peer]\nPublicKey = peer\n"
    )

    assert parsed.values["PostUp"].startswith("iptables -I FORWARD")


def test_replace_generation_directives_preserves_legacy_unknown_and_peers():
    source = AwgInterfaceDirectives.parse(
        AWG3.replace("KeepaliveTimeout = 10\n", "KeepaliveTimeout = 10\nRandomTrailers = 55\n")
    ).for_mode("3.1")
    target = """[Interface]
PrivateKey = mobile-private
Address = 10.68.68.1/24
Jc = 8
FutureUpstreamSetting = retained

[Peer]
PublicKey = mobile-peer
"""

    rendered = source.replace_generation_directives(target)

    assert "HeaderProtectionKey = header-secret" in rendered
    assert "RandomTrailers = 55" in rendered
    assert "Jc = 8" in rendered
    assert "FutureUpstreamSetting = retained" in rendered
    assert "PublicKey = mobile-peer" in rendered


def test_configure_projects_validated_generation_directives_to_mobile(tmp_path):
    desktop = tmp_path / "awg0.conf"
    mobile = tmp_path / "awg1.conf"
    desktop.write_text(AWG3, encoding="utf-8")
    mobile.write_text("[Interface]\nPrivateKey = mobile\nAddress = 10.68.68.1/24\n", encoding="utf-8")
    user = User(
        email="a@example.com",
        uuid="a",
        credentials={
            "amneziawg": {"private_key": "a", "public_key": "a", "preshared_key": "a"},
            "amneziawg_mobile": {"private_key": "b", "public_key": "b", "preshared_key": "b"},
        },
    )
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                enabled=True,
                config={
                    "protocol_mode": "3.0",
                    "profiles": {
                        "desktop": {"server_private_key": "desktop", "network": "10.67.67.0/24"},
                        "mobile": {"server_private_key": "mobile", "network": "10.68.68.0/24"},
                    },
                },
            )
        },
        users=[user],
    )
    plugin = AmneziaWGPlugin()

    with (
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF", desktop),
        patch("hydra.plugins.amneziawg.plugin.AWG_CONF_1", mobile),
    ):
        plugin.configure(state)

    assert "HeaderProtectionKey = header-secret" in (plugin._pending_conf_1 or "")
    assert "KeepaliveTimeout = 10" in (plugin._pending_conf_1 or "")


def test_summary_redacts_secret_values():
    summary = AwgInterfaceDirectives.parse(AWG3).for_mode("3.0").summary()

    assert summary == {"mode": "3.0", "generation_directives": "present"}
    assert "header-secret" not in str(summary)
