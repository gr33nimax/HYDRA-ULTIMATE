from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state_models import AppState
from hydra.services import traffic_daemon
from hydra.services.traffic_attribution import TrafficEvidence


def test_traffic_daemon_feeds_the_calls_sampler_after_accounting() -> None:
    state = AppState()
    state.network.clash_api_enabled = True
    telemetry = MagicMock()

    with patch.object(traffic_daemon, "load_state", return_value=state), patch.object(
        traffic_daemon,
        "_fetch_connections",
        return_value=[],
    ), patch.object(
        traffic_daemon,
        "collect_traffic_evidence",
        return_value=TrafficEvidence(),
    ), patch.object(
        traffic_daemon,
        "update_state",
        side_effect=lambda operation: (state, operation(state)),
    ), patch.object(
        traffic_daemon,
        "CALLS_TELEMETRY",
        telemetry,
    ), patch.object(traffic_daemon, "_write_log"), patch.object(
        traffic_daemon.time,
        "sleep",
        side_effect=SystemExit,
    ):
        with pytest.raises(SystemExit):
            traffic_daemon.run_daemon()

    telemetry.record.assert_called_once_with(state)


def test_traffic_daemon_records_a_categorical_clash_api_outage() -> None:
    state = AppState()
    state.network.clash_api_enabled = True
    telemetry = MagicMock()

    with patch.object(traffic_daemon, "load_state", return_value=state), patch.object(
        traffic_daemon,
        "_fetch_connections",
        side_effect=urllib.error.URLError("offline"),
    ), patch.object(
        traffic_daemon,
        "CALLS_TELEMETRY",
        telemetry,
    ), patch.object(traffic_daemon, "_write_log"), patch.object(
        traffic_daemon.time,
        "sleep",
        side_effect=SystemExit,
    ):
        with pytest.raises(SystemExit):
            traffic_daemon.run_daemon()

    telemetry.record_event.assert_called_once_with("clash_api_unavailable")
