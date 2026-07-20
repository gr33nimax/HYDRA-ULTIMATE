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
    assert servers[0]["type"] == "udp"
    assert servers[0]["tag"] == "dnscrypt-local"
    assert servers[0]["server"] == "127.0.0.1"
    assert servers[0]["server_port"] == DNSCRYPT_PORT


@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._installed")
@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
def test_dnscrypt_install(mock_write_config, mock_host, mock_installed):
    p = DNSCryptPlugin()
    
    # 1. Если уже установлен (должен записать конфиг и запустить службу)
    mock_installed.return_value = True
    mock_host.run.return_value = MagicMock(returncode=0)
    assert p.install() is True
    mock_write_config.assert_called_once()
    mock_host.run.assert_called_once_with(["systemctl", "enable", "--now", "dnscrypt-proxy"])

    # Сбрасываем моки
    mock_write_config.reset_mock()
    mock_host.run.reset_mock()

    # 2. Если не установлен, пробуем установить успешно
    mock_installed.return_value = False
    mock_host.run.return_value = MagicMock(returncode=0)
    assert p.install() is True
    mock_write_config.assert_called_once()
    assert mock_host.run.call_count == 3


@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_uninstall(mock_conf, mock_host):
    p = DNSCryptPlugin()
    mock_conf.exists.return_value = True
    mock_host.run.return_value = MagicMock(returncode=0)
    
    assert p.uninstall() is True
    mock_host.systemd.assert_any_call("stop", "dnscrypt-proxy")
    mock_host.systemd.assert_any_call("disable", "dnscrypt-proxy")
    mock_host.run.assert_called_once_with(
        ["apt-get", "remove", "-y", "-qq", "dnscrypt-proxy"], timeout=60,
    )
    mock_conf.unlink.assert_called_once()


@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._installed")
@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_status(mock_conf, mock_host, mock_installed):
    p = DNSCryptPlugin()
    
    # 1. Не установлен
    mock_installed.return_value = False
    status = p.status()
    assert status.installed is False
    assert status.running is False

    # 2. Установлен, но не запущен
    mock_installed.return_value = True
    mock_conf.exists.return_value = True
    mock_host.systemd.return_value = MagicMock(returncode=1)
    status = p.status()
    assert status.installed is True
    assert status.enabled is True
    assert status.running is False

    # 3. Установлен и запущен
    mock_host.systemd.return_value = MagicMock(returncode=0)
    status = p.status()
    assert status.installed is True
    assert status.running is True


@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
def test_dnscrypt_on_enable_disable(mock_write_config, mock_host):
    p = DNSCryptPlugin()
    state = AppState()
    
    assert state.network.dnscrypt_enabled is False
    mock_host.systemd.return_value = MagicMock(returncode=0)
    
    p.on_enable(state)
    assert state.network.dnscrypt_enabled is True
    assert state.network.dnscrypt_port == DNSCRYPT_PORT
    mock_write_config.assert_called_once()
    mock_host.systemd.assert_any_call("enable", "dnscrypt-proxy")
    mock_host.systemd.assert_any_call("start", "dnscrypt-proxy")

    p.on_disable(state)
    assert state.network.dnscrypt_enabled is False
    mock_host.systemd.assert_any_call("stop", "dnscrypt-proxy")
    mock_host.systemd.assert_any_call("disable", "dnscrypt-proxy")


@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_enable_preserves_existing_config(mock_conf, mock_write_config, mock_host):
    mock_conf.exists.return_value = True
    mock_host.systemd.return_value = MagicMock(returncode=0)
    DNSCryptPlugin().on_enable(AppState())
    mock_write_config.assert_not_called()


@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._installed", return_value=True)
@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCryptPlugin._write_default_config")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_install_preserves_existing_config(mock_conf, mock_write, mock_host, _mock_installed):
    mock_conf.exists.return_value = True
    mock_host.run.return_value = MagicMock(returncode=0)

    assert DNSCryptPlugin().install() is True
    mock_write.assert_not_called()


@patch("hydra.plugins.dnscrypt.plugin.HOST")
def test_dnscrypt_enable_reports_service_failure(mock_host):
    mock_host.systemd.side_effect = [MagicMock(returncode=0), MagicMock(returncode=1)]

    try:
        DNSCryptPlugin().on_enable(AppState())
    except RuntimeError as exc:
        assert "dnscrypt-proxy" in str(exc)
    else:
        raise AssertionError("service failure must not be reported as success")


@patch("hydra.plugins.dnscrypt.plugin.HOST")
@patch("hydra.plugins.dnscrypt.plugin.DNSCRYPT_CONF")
def test_dnscrypt_repair_restores_config(mock_conf, mock_host):
    mock_conf.exists.return_value = True
    mock_conf.read_bytes.return_value = b"custom config"
    mock_host.run.return_value = MagicMock(returncode=0)

    assert DNSCryptPlugin().repair_installation(enabled=True) is True

    mock_host.atomic_write.assert_called_once_with(mock_conf, b"custom config")
    assert mock_host.run.call_args_list[-1].args[0] == [
        "systemctl", "enable", "--now", "dnscrypt-proxy",
    ]


def test_get_dnscrypt_bin():
    from hydra.plugins.dnscrypt.plugin import get_dnscrypt_bin
    
    # Имя файла проверяется с прямыми и обратными слешами для поддержки Windows путей в тестах
    def _is_sbin(p):
        s = str(p).replace("\\", "/")
        return s.endswith("/usr/sbin/dnscrypt-proxy")
        
    def _is_bin(p):
        s = str(p).replace("\\", "/")
        return s.endswith("/usr/bin/dnscrypt-proxy")

    with patch("hydra.plugins.dnscrypt.plugin.Path.exists", autospec=True) as mock_exists:
        # 1. Если есть в /usr/sbin
        mock_exists.side_effect = lambda self_path: _is_sbin(self_path)
        assert _is_sbin(get_dnscrypt_bin())
        
    with patch("hydra.plugins.dnscrypt.plugin.Path.exists", autospec=True) as mock_exists:
        # 2. Если есть в /usr/bin
        mock_exists.side_effect = lambda self_path: _is_bin(self_path)
        assert _is_bin(get_dnscrypt_bin())
        
    with patch("hydra.plugins.dnscrypt.plugin.Path.exists", autospec=True) as mock_exists:
        # 3. Если нет нигде
        mock_exists.return_value = False
        assert _is_sbin(get_dnscrypt_bin())


def test_apply_server_names_handles_multiline_toml_atomically(tmp_path):
    from hydra.plugins.dnscrypt import manager

    config = tmp_path / "dnscrypt-proxy.toml"
    config.write_text(
        "listen_addresses = ['127.0.0.1:5300']\n"
        "server_names = [\n  'old-one',\n  'old-two',\n]\nmax_clients = 250\n",
        encoding="utf-8",
    )
    host = MagicMock()
    host.run.return_value = MagicMock(returncode=0)
    host.systemd.return_value = MagicMock(returncode=0)

    with patch.object(manager, "DNSCRYPT_CONF", config), patch.object(manager, "HOST", host):
        assert manager._apply_server_names(["cloudflare", "quad9-dnscrypt-ip4-filter-pri"]) is True

    written = host.atomic_write.call_args_list[0].args[1]
    assert "server_names = ['cloudflare', 'quad9-dnscrypt-ip4-filter-pri']" in written
    assert "old-one" not in written
    host.systemd.assert_called_once_with("restart", "dnscrypt-proxy")


def test_apply_server_names_rolls_back_when_validation_fails(tmp_path):
    from hydra.plugins.dnscrypt import manager

    config = tmp_path / "dnscrypt-proxy.toml"
    original = b"listen_addresses = ['127.0.0.1:5300']\nserver_names = ['old']\n"
    config.write_bytes(original)
    host = MagicMock()
    host.run.return_value = MagicMock(returncode=1)

    with patch.object(manager, "DNSCRYPT_CONF", config), patch.object(manager, "HOST", host):
        assert manager._apply_server_names(["cloudflare"]) is False

    assert host.atomic_write.call_args_list[-1].args[1] == original
    host.systemd.assert_not_called()

