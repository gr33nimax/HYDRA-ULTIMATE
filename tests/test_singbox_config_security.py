from __future__ import annotations

from hydra.core.singbox_config_security import redacted_debug_config


def test_call_secrets_are_removed_from_singbox_debug_config() -> None:
    source = {
        "inbounds": [{
            "type": "call",
            "cookies": [{"name": "remixsid", "value": "secret"}],
            "join_link": "https://vk.com/call/join/shared-room",
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }

    redacted = redacted_debug_config(source)

    assert redacted["inbounds"][0]["cookies"] == "<redacted>"
    assert redacted["inbounds"][0]["join_link"] == "<redacted>"
    assert redacted["outbounds"] == source["outbounds"]
    assert source["inbounds"][0]["join_link"].endswith("shared-room")
