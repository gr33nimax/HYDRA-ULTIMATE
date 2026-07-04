"""tests/test_dnscrypt_plugin.py — Тесты для плагина DNSCrypt."""
from pathlib import Path
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.dnscrypt.plugin import DNSCryptPlugin, DNSCRYPT_PORT
from hydra.core.state import AppState, PluginState


def test_dnscrypt_metadata():
    p = DNSCryptPlugin()
    assert p.meta.name == "dnscrypt"
    assert p.meta.category.value == "enhancement"
    assert p.meta.version == "2.0.0"


def test_dnscrypt_configure():
    p = DNSCryptPlugin()
    state = AppState()
    frag = p.configure(state)

    assert frag.dns != {}
    assert "servers" in frag.dns
    servers = frag.dns["servers"]
    assert len(servers) == 1
    assert servers[0]["tag"] == "dnscrypt-local"
    assert servers[0]["address"] == f"127.0.0.1:{DNSCRYPT_PORT}"
    assert servers[0]["detour"] == "direct"


@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._installed")
@patch("hydra.plugins.dnscrypt.plugin.subprocess.run")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
def test_dnscrypt_install(mock_write_config, mock_run, mock_installed):
    p = DNSCryptPlugin()
    
    # 1. Если уже установлен
    mock_installed.return_value = True
    assert p.install() is True
    mock_run.assert_not_called()

    # 2. Если не установлен, пробуем установить успешно
    mock_installed.return_value = False
    mock_run.return_value = MagicMock(returncode=0)
    assert p.install() is True
    mock_write_config.assert_called_once()
    assert mock_run.call_count >= 2  # apt-get install и systemctl enable --now


@patch("hydra.plugins.dnscrypt.plugin.subprocess.run")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_uninstall(mock_conf, mock_run):
    p = DNSCryptPlugin()
    mock_conf.exists.return_value = True
    
    assert p.uninstall() is True
    mock_run.assert_any_call(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
    mock_run.assert_any_call(["systemctl", "disable", "dnscrypt-proxy"], capture_output=True)
    mock_conf.unlink.assert_called_once()


@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._installed")
@patch("hydra.plugins.dnscrypt.plugin.subprocess.run")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_status(mock_conf, mock_run, mock_installed):
    p = DNSCryptPlugin()
    
    # 1. Не установлен
    mock_installed.return_value = False
    status = p.status()
    assert status.installed is False
    assert status.running is False

    # 2. Установлен, но не запущен
    mock_installed.return_value = True
    mock_conf.exists.return_value = True
    mock_run.return_value = MagicMock(returncode=1)  # systemctl is-active -> inactive
    status = p.status()
    assert status.installed is True
    assert status.enabled is True
    assert status.running is False

    # 3. Установлен и запущен
    mock_run.return_value = MagicMock(returncode=0)  # systemctl is-active -> active
    status = p.status()
    assert status.installed is True
    assert status.running is True


@patch("hydra.plugins.dnscrypt.plugin.subprocess.run")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
def test_dnscrypt_on_enable_disable(mock_write_config, mock_run):
    p = DNSCryptPlugin()
    state = AppState()
    
    assert state.network.dnscrypt_enabled is False
    
    p.on_enable(state)
    assert state.network.dnscrypt_enabled is True
    assert state.network.dnscrypt_port == DNSCRYPT_PORT
    mock_write_config.assert_called_once()
    mock_run.assert_any_call(["systemctl", "enable", "dnscrypt-proxy"], capture_output=True)
    mock_run.assert_any_call(["systemctl", "start", "dnscrypt-proxy"], capture_output=True)

    p.on_disable(state)
    assert state.network.dnscrypt_enabled is False
    mock_run.assert_any_call(["systemctl", "stop", "dnscrypt-proxy"], capture_output=True)
    mock_run.assert_any_call(["systemctl", "disable", "dnscrypt-proxy"], capture_output=True)
