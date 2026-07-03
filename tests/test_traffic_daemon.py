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

