"""Telemt's bounded Hydra settings and pure upstream renderer."""

import pytest

from hydra.plugins.telemt import configuration


def test_normal_fake_tls_settings_render_upstream_357_fields():
    settings = configuration.TelemtSettings(port=443, tls_domain="mask.example")

    toml = configuration.render_toml(settings, {"alice": "a" * 32})

    assert 'log_level = "normal"' in toml
    assert "port = 443" in toml
    assert 'ip = "0.0.0.0"' in toml
    assert 'tls_domain = "mask.example"' in toml
    assert "tls_emulation = true" in toml
    assert '"alice" = "' + "a" * 32 + '"' in toml
    assert "fake_cert_len" not in toml
    assert "client_mss" not in toml


def test_base64_user_keys_are_quoted_for_toml():
    """A derived username may contain +, / or =; an unquoted key is invalid TOML."""
    settings = configuration.TelemtSettings(port=443, tls_domain="mask.example")

    toml = configuration.render_toml(settings, {"u+ab/cd=": "a" * 32})

    assert '"u+ab/cd=" = "' + "a" * 32 + '"' in toml

    tomllib = pytest.importorskip("tomllib", reason="stdlib TOML parser needs Python 3.11+")
    assert tomllib.loads(toml)["access"]["users"]["u+ab/cd="] == "a" * 32


@pytest.mark.parametrize(
    "kwargs",
    (
        {"port": 0, "tls_domain": "mask.example"},
        {"port": 65536, "tls_domain": "mask.example"},
        {"port": 443, "tls_domain": ""},
        {"port": 443, "tls_domain": "mask.example", "network": "bogus"},
        {"port": 443, "tls_domain": "mask.example", "log_level": "trace"},
    ),
)
def test_settings_reject_invalid_or_unsupported_values(kwargs):
    with pytest.raises(ValueError):
        configuration.TelemtSettings(**kwargs)


def test_advanced_settings_change_only_their_documented_output():
    settings = configuration.TelemtSettings(
        port=8443,
        tls_domain="mask.example",
        network="ipv6",
        use_middle_proxy=True,
        log_level="debug",
    )

    toml = configuration.render_toml(settings, {})

    assert 'log_level = "debug"' in toml
    assert "use_middle_proxy = true" in toml
    assert 'ip = "::"' in toml
    assert 'ip = "0.0.0.0"' not in toml
