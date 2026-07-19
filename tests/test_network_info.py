from unittest.mock import patch

from hydra.ui import network_info


def test_private_ip_detection():
    assert network_info.is_private_ip("10.0.0.1") is True
    assert network_info.is_private_ip("172.16.0.1") is True
    assert network_info.is_private_ip("192.168.1.1") is True
    assert network_info.is_private_ip("8.8.8.8") is False


def test_network_probe_starts_only_once():
    with patch.object(network_info.threading, "Thread") as thread:
        with patch.object(network_info, "_started", False):
            network_info.start()
            network_info.start()
    thread.assert_called_once()
