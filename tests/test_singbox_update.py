import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.singbox import parse_version, update_kernel, SINGBOX_BIN, SINGBOX_CONFIG
from hydra.core.state import AppState


def _legacy_dns_config() -> dict:
    return {
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://dns.quad9.net/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "detour": "direct",
                },
                {
                    "tag": "dns-direct",
                    "address": "1.1.1.1",
                    "detour": "direct",
                },
            ],
            "rules": [],
        },
    }


def test_parse_version():
    assert parse_version("1.18.0-extended") == (1, 18, 0)
    assert parse_version("v1.19.1") == (1, 19, 1)
    assert parse_version("1.19.0-extended-b8") == (1, 19, 0, 8)
    assert parse_version("1.13.14-extended-2.5.0") == (1, 13, 14, 2, 5, 0)
    assert parse_version("v1.13.14-extended-2.5.2") == (1, 13, 14, 2, 5, 2)
    assert parse_version(None) == (0,)
    assert parse_version("invalid") == (0,)


@pytest.fixture
def mock_singbox_paths(tmp_path):
    bin_path = tmp_path / "sing-box"
    config_path = tmp_path / "config.json"
    bin_path.write_text("original binary content")
    config_path.write_text("{}")
    
    with patch("hydra.core.singbox.SINGBOX_BIN", bin_path), \
         patch("hydra.core.singbox.SINGBOX_CONFIG", config_path):
        yield bin_path, config_path


def test_update_kernel_success(mock_singbox_paths):
    bin_path, config_path = mock_singbox_paths
    
    state = AppState()
    state.install["singbox_update_available"] = True
    state.install["singbox_latest_version"] = "v1.19.0"

    def dummy_update_state(mutator):
        mutator(state)
        return state, None

    # Simulate success: install updates the binary file content
    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success) as mock_install, \
         patch("hydra.core.singbox.get_version", return_value="1.19.0"), \
         patch("hydra.core.singbox._run") as mock_run, \
         patch("hydra.core.singbox.start", return_value=True) as mock_start, \
         patch("hydra.core.state.update_state", side_effect=dummy_update_state):
        
        run_result = MagicMock()
        run_result.returncode = 0
        mock_run.return_value = run_result

        success, msg = update_kernel()
        assert success is True
        assert "успешно обновлено" in msg
        assert bin_path.read_text() == "new binary content"
        # backup is removed
        assert not bin_path.with_suffix(".bak").exists()
        assert state.install.get("singbox_update_available") is None


def test_update_kernel_migrates_legacy_dns_before_config_check(
    mock_singbox_paths,
):
    bin_path, config_path = mock_singbox_paths
    config_path.write_text(json.dumps(_legacy_dns_config()), encoding="utf-8")

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    def check_migrated_config(_command):
        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert config["dns"]["strategy"] == "ipv4_only"
        assert config["dns"]["servers"][0] == {
            "type": "https",
            "tag": "dns-remote",
            "server": "dns.quad9.net",
            "domain_resolver": "dns-direct",
        }
        assert config["dns"]["servers"][1] == {
            "type": "udp",
            "tag": "dns-direct",
            "server": "1.1.1.1",
        }
        return MagicMock(returncode=0)

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.13.16-extended-2.6.1"), \
         patch("hydra.core.singbox._run", side_effect=check_migrated_config), \
         patch("hydra.core.singbox.start", return_value=True):
        success, message = update_kernel()

    assert success is True
    assert "2.6.1" in message
    assert not config_path.with_name(f"{config_path.name}.upgrade.bak").exists()


def test_update_kernel_restores_legacy_dns_when_new_config_is_rejected(
    mock_singbox_paths,
):
    bin_path, config_path = mock_singbox_paths
    original = _legacy_dns_config()
    config_path.write_text(json.dumps(original), encoding="utf-8")

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    rejected = MagicMock(returncode=1, stderr="dns transport rejected")
    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.13.16-extended-2.6.1"), \
         patch("hydra.core.singbox._run", return_value=rejected), \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=True):
        success, message = update_kernel()

    assert success is False
    assert "dns transport rejected" in message
    assert bin_path.read_text() == "original binary content"
    assert json.loads(config_path.read_text(encoding="utf-8")) == original
    assert not config_path.with_name(f"{config_path.name}.upgrade.bak").exists()


def test_update_kernel_rolls_back_when_dns_migration_cannot_read_config(
    mock_singbox_paths,
):
    bin_path, config_path = mock_singbox_paths
    config_path.write_text("{broken", encoding="utf-8")

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.13.16-extended-2.6.1"), \
         patch("hydra.core.singbox._run") as mock_run, \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=True):
        success, message = update_kernel()

    assert success is False
    assert "Не удалось мигрировать DNS-конфигурацию" in message
    assert "Выполнен откат" in message
    assert bin_path.read_text() == "original binary content"
    assert config_path.read_text(encoding="utf-8") == "{broken"
    assert not config_path.with_name(f"{config_path.name}.upgrade.bak").exists()
    mock_run.assert_not_called()


def test_update_kernel_fail_installation(mock_singbox_paths):
    bin_path, config_path = mock_singbox_paths
    
    # Simulate failed install: it modifies/corrupts the binary then returns False
    def mock_install_fail(force=False):
        bin_path.write_text("corrupted content")
        return False

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_fail), \
         patch("hydra.core.singbox.stop") as mock_stop, \
         patch("hydra.core.singbox.start") as mock_start:
        
        success, msg = update_kernel()
        assert success is False
        assert "Не удалось скачать или распаковать" in msg
        # Verification that the original file is restored
        assert bin_path.read_text() == "original binary content"
        mock_start.assert_called_once()


def test_update_kernel_reports_install_failure_detail(mock_singbox_paths):
    bin_path, _ = mock_singbox_paths

    def mock_install_fail(force=False):
        bin_path.write_text("corrupted content")
        from hydra.core import singbox

        singbox._set_error("GitHub API вернул HTTP 403: rate limit")
        return False

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_fail), \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=True):
        success, msg = update_kernel()

    assert success is False
    assert "HTTP 403" in msg
    assert bin_path.read_text() == "original binary content"


def test_update_kernel_fail_verification(mock_singbox_paths):
    bin_path, config_path = mock_singbox_paths
    
    def mock_install_succ(force=False):
        bin_path.write_text("broken executable")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_succ), \
         patch("hydra.core.singbox.get_version", return_value=None), \
         patch("hydra.core.singbox.stop") as mock_stop, \
         patch("hydra.core.singbox.start") as mock_start:
        
        success, msg = update_kernel()
        assert success is False
        assert "Новый бинарник не запускается" in msg
        assert bin_path.read_text() == "original binary content"
        mock_start.assert_called_once()


def test_update_kernel_rolls_back_when_version_probe_raises(mock_singbox_paths):
    bin_path, _ = mock_singbox_paths

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch(
             "hydra.core.singbox.get_version",
             side_effect=RuntimeError("exec format error"),
         ), \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=True):
        success, msg = update_kernel()

    assert success is False
    assert "exec format error" in msg
    assert "Выполнен откат" in msg
    assert bin_path.read_text() == "original binary content"


def test_update_kernel_fail_config_check(mock_singbox_paths):
    bin_path, config_path = mock_singbox_paths
    
    def mock_install_succ(force=False):
        bin_path.write_text("incompatible config binary")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_succ), \
         patch("hydra.core.singbox.get_version", return_value="1.19.0"), \
         patch("hydra.core.singbox._run") as mock_run, \
         patch("hydra.core.singbox.stop") as mock_stop, \
         patch("hydra.core.singbox.start") as mock_start:
        
        run_result = MagicMock()
        run_result.returncode = 1  # config check fails
        mock_run.return_value = run_result

        success, msg = update_kernel()
        assert success is False
        assert "Конфигурация несовместима" in msg
        assert bin_path.read_text() == "original binary content"
        mock_start.assert_called_once()


def test_update_kernel_rolls_back_when_config_check_raises(mock_singbox_paths):
    bin_path, _ = mock_singbox_paths

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.19.0"), \
         patch(
             "hydra.core.singbox._run",
             side_effect=RuntimeError("config check timed out"),
         ), \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=True):
        success, msg = update_kernel()

    assert success is False
    assert "config check timed out" in msg
    assert bin_path.read_text() == "original binary content"


def test_update_kernel_fail_service_start(mock_singbox_paths):
    bin_path, config_path = mock_singbox_paths
    
    def mock_install_succ(force=False):
        bin_path.write_text("unrunnable service binary")
        return True

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_succ), \
         patch("hydra.core.singbox.get_version", return_value="1.19.0"), \
         patch("hydra.core.singbox._run") as mock_run, \
         patch("hydra.core.singbox.stop") as mock_stop, \
         patch("hydra.core.singbox.start", side_effect=[False, True]) as mock_start:  # first start fails, second rollback start succeeds
        
        run_result = MagicMock()
        run_result.returncode = 0
        mock_run.return_value = run_result

        success, msg = update_kernel()
        assert success is False
        assert "Служба не смогла запуститься" in msg
        assert bin_path.read_text() == "original binary content"
        assert mock_start.call_count == 2


def test_update_kernel_rolls_back_when_service_start_raises(mock_singbox_paths):
    bin_path, _ = mock_singbox_paths

    def mock_install_success(force=False):
        bin_path.write_text("new binary content")
        return True

    run_result = MagicMock(returncode=0)
    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.19.0"), \
         patch("hydra.core.singbox._run", return_value=run_result), \
         patch("hydra.core.singbox.stop"), \
         patch(
             "hydra.core.singbox.start",
             side_effect=[RuntimeError("systemd timeout"), True],
         ) as mock_start:
        success, msg = update_kernel()

    assert success is False
    assert "systemd timeout" in msg
    assert bin_path.read_text() == "original binary content"
    assert mock_start.call_count == 2


def test_update_kernel_reports_failed_service_restore(mock_singbox_paths):
    bin_path, _ = mock_singbox_paths

    def mock_install_fail(force=False):
        bin_path.write_text("corrupted content")
        return False

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.install", side_effect=mock_install_fail), \
         patch("hydra.core.singbox.stop"), \
         patch("hydra.core.singbox.start", return_value=False):
        success, msg = update_kernel()

    assert success is False
    assert "служба не запустилась" in msg
    assert bin_path.read_text() == "original binary content"


def test_update_kernel_accepts_binary_found_outside_usr_local(tmp_path):
    installed_bin = tmp_path / "usr-bin-sing-box"
    target_bin = tmp_path / "usr-local-sing-box"
    config_path = tmp_path / "config.json"
    installed_bin.write_text("system binary")
    config_path.write_text("{}")

    def mock_install_success(force=False):
        target_bin.write_text("new extended binary")
        return True

    run_result = MagicMock(returncode=0)
    with patch("hydra.core.singbox._find_singbox", return_value=installed_bin), \
         patch("hydra.core.singbox.SINGBOX_BIN", target_bin), \
         patch("hydra.core.singbox.SINGBOX_CONFIG", config_path), \
         patch("hydra.core.singbox.is_running", return_value=False), \
         patch("hydra.core.singbox.install", side_effect=mock_install_success), \
         patch("hydra.core.singbox.get_version", return_value="1.13.11-extended-2.1.0"), \
         patch("hydra.core.singbox._run", return_value=run_result):
        success, _ = update_kernel()

    assert success is True
    assert target_bin.read_text() == "new extended binary"
