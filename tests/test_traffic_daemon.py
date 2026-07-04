"""tests/test_traffic_daemon.py — Тесты для фонового демона трафика."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from hydra.core.state import AppState, User
from hydra.services.traffic_daemon import run_daemon

def test_daemon_collects_traffic_from_clash_api():
    state = AppState()
    state.network.clash_api_enabled = True
    state.network.clash_api_port = 9090
    state.network.clash_api_secret = "mysecret"
    
    user1 = User(email="user1@example.com", uuid="u1")
    user2 = User(email="user2@example.com", uuid="u2")
    state.users = [user1, user2]
    
    api_response_1 = {
        "connections": [
            {
                "id": "conn1",
                "metadata": {"user": "user1@example.com", "inboundTag": "anytls-in"},
                "upload": 100,
                "download": 200
            },
            {
                "id": "conn2",
                "metadata": {"user": "user2@example.com", "inboundTag": "mieru-in"},
                "upload": 50,
                "download": 50
            }
        ]
    }
    
    api_response_2 = {
        "connections": [
            {
                "id": "conn1",
                "metadata": {"user": "user1@example.com", "inboundTag": "anytls-in"},
                "upload": 150,
                "download": 250
            },
            {
                "id": "conn3",
                "metadata": {"user": "user2@example.com", "inboundTag": "mieru-in"},
                "upload": 200,
                "download": 200
            }
        ]
    }
    
    response1 = MagicMock()
    response1.__enter__.return_value = response1
    response1.read.return_value = json.dumps(api_response_1).encode("utf-8")
    
    response2 = MagicMock()
    response2.__enter__.return_value = response2
    response2.read.return_value = json.dumps(api_response_2).encode("utf-8")
    
    responses = [response1, response2]

    
    sleep_count = 0
    def mock_sleep(seconds):
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count >= 2:
            raise SystemExit()
            
    saved_states = []
    def mock_save(st):
        saved_states.append(st)
        
    # We patch _log by patching the print or log function if needed, or by allowing it to fail silently.
    import urllib.request
    
    with patch("hydra.services.traffic_daemon.load_state", return_value=state), \
         patch("hydra.services.traffic_daemon.save_state", side_effect=mock_save), \
         patch("hydra.services.traffic_daemon.urllib.request.urlopen") as mock_urlopen, \
         patch("time.sleep", side_effect=mock_sleep), \
         patch("hydra.services.traffic_daemon.Path") as mock_path:
         
        # Set up path mock to avoid FileNotFoundError on /var/log/
        mock_path.return_value.open.return_value.__enter__.return_value = MagicMock()
        mock_urlopen.side_effect = responses
        
        with pytest.raises(SystemExit):
            run_daemon()
            
        assert user1.traffic_used_bytes == 400
        assert user2.traffic_used_bytes == 500
        assert user1.credentials["anytls"]["traffic_used_bytes"] == 400
        assert user2.credentials["mieru"]["traffic_used_bytes"] == 500
        assert len(saved_states) >= 2


def test_daemon_collects_anytls_traffic_using_journalctl():
    state = AppState()
    state.network.clash_api_enabled = True
    state.network.clash_api_port = 9090
    state.network.clash_api_secret = "mysecret"
    
    user = User(email="tester2", uuid="u2")
    state.users = [user]
    
    api_response = {
        "connections": [
            {
                "id": "conn-anytls-1",
                "metadata": {
                    "destinationIP": "",
                    "destinationPort": "443",
                    "dnsMode": "normal",
                    "host": "ogs.google.com",
                    "network": "tcp",
                    "processPath": "",
                    "sourceIP": "127.0.0.1",
                    "sourcePort": "38308",
                    "type": "anytls/anytls-in"
                },
                "upload": 100,
                "download": 300
            }
        ]
    }
    
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    
    fake_journal = """
Jul 03 19:42:56 sing-box[222339]: +0300 2026-07-03 19:42:56 INFO [2371721395 0ms] inbound/anytls[anytls-in]: inbound connection from 127.0.0.1:38308
Jul 03 19:42:56 sing-box[222339]: +0300 2026-07-03 19:42:56 INFO [2371721395 89ms] inbound/anytls[anytls-in]: [tester2] inbound connection to rr2---sn-oj5hn5-5v.googlevideo.com:443
"""
    
    mock_sub = MagicMock()
    mock_sub.returncode = 0
    mock_sub.stdout = fake_journal
    
    call_count = 0
    def mock_sleep(secs):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise SystemExit()
            
    saved_states = []
    def mock_save(st):
        saved_states.append(st)
        
    with patch("hydra.services.traffic_daemon.load_state", return_value=state), \
         patch("hydra.services.traffic_daemon.save_state", side_effect=mock_save), \
         patch("hydra.services.traffic_daemon.urllib.request.urlopen", return_value=mock_resp), \
         patch("time.sleep", side_effect=mock_sleep), \
         patch("subprocess.run", return_value=mock_sub), \
         patch("hydra.services.traffic_daemon.Path") as mock_path:
         
        mock_path.return_value.open.return_value.__enter__.return_value = MagicMock()
        
        with pytest.raises(SystemExit):
            run_daemon()
            
        assert user.traffic_used_bytes == 400
        assert user.credentials["anytls"]["traffic_used_bytes"] == 400
        assert len(saved_states) >= 1


def test_daemon_collects_trusttunnel_traffic_using_journalctl():
    state = AppState()
    state.network.clash_api_enabled = True
    state.network.clash_api_port = 9090
    state.network.clash_api_secret = "mysecret"
    
    user = User(email="tester_tt@example.com", uuid="u_tt")
    state.users = [user]
    
    api_response = {
        "connections": [
            {
                "id": "1284697157",
                "metadata": {
                    "destinationIP": "",
                    "destinationPort": "443",
                    "dnsMode": "normal",
                    "host": "google.com",
                    "network": "tcp",
                    "processPath": "",
                    "sourceIP": "95.84.12.34",
                    "sourcePort": "54321",
                    "inboundTag": "trusttunnel-in"
                },
                "upload": 100,
                "download": 300
            }
        ]
    }
    
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    
    fake_journal = """
Jul 03 19:42:56 sing-box[222339]: +0300 2026-07-03 19:42:56 INFO inbound/trusttunnel[trusttunnel-in]: [tester_tt@example.com] inbound connection to google.com:443
"""
    
    mock_sub = MagicMock()
    mock_sub.returncode = 0
    mock_sub.stdout = fake_journal
    
    call_count = 0
    def mock_sleep(secs):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise SystemExit()
            
    saved_states = []
    def mock_save(st):
        saved_states.append(st)
        
    with patch("hydra.services.traffic_daemon.load_state", return_value=state), \
         patch("hydra.services.traffic_daemon.save_state", side_effect=mock_save), \
         patch("hydra.services.traffic_daemon.urllib.request.urlopen", return_value=mock_resp), \
         patch("time.sleep", side_effect=mock_sleep), \
         patch("subprocess.run", return_value=mock_sub), \
         patch("hydra.services.traffic_daemon.Path") as mock_path:
         
        mock_path.return_value.open.return_value.__enter__.return_value = MagicMock()
        
        with pytest.raises(SystemExit):
            run_daemon()
            
        assert user.traffic_used_bytes == 400
        assert user.credentials["trusttunnel"]["traffic_used_bytes"] == 400
        assert len(saved_states) >= 1


def test_daemon_collects_mieru_traffic_using_journalctl():
    state = AppState()
    state.network.clash_api_enabled = True
    state.network.clash_api_port = 9090
    state.network.clash_api_secret = "mysecret"
    
    user = User(email="tester_mieru@example.com", uuid="u_mieru")
    state.users = [user]
    
    api_response = {
        "connections": [
            {
                "id": "conn-mieru-1",
                "metadata": {
                    "destinationIP": "1.1.1.1",
                    "destinationPort": "443",
                    "dnsMode": "normal",
                    "host": "cloudflare.com",
                    "network": "tcp",
                    "processPath": "",
                    "sourceIP": "::ffff:5.180.242.78",
                    "sourcePort": "6481",
                    "type": "mieru/mieru-in"
                },
                "upload": 200,
                "download": 800
            }
        ]
    }
    
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    
    fake_journal = """
Jul 04 17:13:23 sing-box[222339]: +0300 2026-07-04 17:13:23 INFO [898639574 1ms] inbound/mieru[mieru-in]: inbound TCP connection from [::ffff:5.180.242.78]:6481 to cloudflare.com:443
Jul 04 17:13:23 sing-box[222339]: +0300 2026-07-04 17:13:23 INFO [898639574 1ms] inbound/mieru[mieru-in]: [tester_mieru@example.com] inbound TCP connection
"""
    
    mock_sub = MagicMock()
    mock_sub.returncode = 0
    mock_sub.stdout = fake_journal
    
    call_count = 0
    def mock_sleep(secs):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            raise SystemExit()
            
    saved_states = []
    def mock_save(st):
        saved_states.append(st)
        
    with patch("hydra.services.traffic_daemon.load_state", return_value=state), \
         patch("hydra.services.traffic_daemon.save_state", side_effect=mock_save), \
         patch("hydra.services.traffic_daemon.urllib.request.urlopen", return_value=mock_resp), \
         patch("time.sleep", side_effect=mock_sleep), \
         patch("subprocess.run", return_value=mock_sub), \
         patch("hydra.services.traffic_daemon.Path") as mock_path:
         
        mock_path.return_value.open.return_value.__enter__.return_value = MagicMock()
        
        with pytest.raises(SystemExit):
            run_daemon()
            
        assert user.traffic_used_bytes == 1000
        assert user.credentials["mieru"]["traffic_used_bytes"] == 1000
        assert len(saved_states) >= 1



