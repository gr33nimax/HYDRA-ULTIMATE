from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState
from hydra.services.system_overview import collect_system_overview


def test_system_overview_collects_hostname_inside_admin_boundary():
    network = SimpleNamespace(
        public_ip="203.0.113.10",
        country_flag="",
        dns="",
    )
    with patch(
        "hydra.services.system_overview.socket.gethostname",
        return_value="hydra-node",
    ), patch(
        "hydra.services.system_overview.network_snapshot",
        return_value=network,
    ), patch(
        "hydra.services.system_overview.local_ip",
        return_value="192.0.2.10",
    ), patch(
        "hydra.services.system_overview._dnscrypt_status",
        return_value=(False, ()),
    ):
        overview = collect_system_overview(
            AppState(),
            host=MagicMock(),
        )

    assert overview.hostname == "hydra-node"
