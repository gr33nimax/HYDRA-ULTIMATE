from __future__ import annotations

import pytest

from hydra.services.creator_sessions import (
    CreatorEndpoint,
    CreatorProviderAvailability,
    CreatorSessionGroup,
    CreatorSessionManager,
    CreatorSessionRequest,
)


class Driver:
    def __init__(self) -> None:
        self.requests = []
        self.rolled_back = False

    def creator_availability(self):
        return CreatorProviderAvailability(True, True)

    def create_sessions(self, request):
        self.requests.append(request)
        endpoints = tuple(
            CreatorEndpoint(f"https://example.test/{index}", f"token-{index}")
            for index in range(request.count)
        )
        return CreatorSessionGroup(request, endpoints)

    def commit_sessions(self, group): return None
    def finalize_sessions(self, group): return None
    def close_sessions(self, group): return None
    def stop_managed_sessions(self, consumer): return True, "stopped"

    def rollback_sessions(self, group):
        self.rolled_back = True


def test_manager_dispatches_calls_and_qwdtt_through_the_same_provider() -> None:
    driver = Driver()
    manager = CreatorSessionManager({"vk": driver})

    calls = manager.create(CreatorSessionRequest("vk", "calls", "transient"))
    qwdtt = manager.create(CreatorSessionRequest("vk", "qwdtt", "managed", count=3))

    assert len(calls.endpoints) == 1
    assert [endpoint.token for endpoint in qwdtt.endpoints] == [
        "token-0",
        "token-1",
        "token-2",
    ]
    assert [request.consumer for request in driver.requests] == ["calls", "qwdtt"]


def test_manager_rejects_multi_session_transient_request_before_driver_call() -> None:
    driver = Driver()
    manager = CreatorSessionManager({"vk": driver})

    with pytest.raises(ValueError, match="one session"):
        manager.create(CreatorSessionRequest("vk", "calls", "transient", count=2))

    assert driver.requests == []


def test_manager_rolls_back_invalid_provider_result() -> None:
    class BrokenDriver(Driver):
        def create_sessions(self, request):
            return CreatorSessionGroup(request, ())

    driver = BrokenDriver()
    manager = CreatorSessionManager({"vk": driver})

    with pytest.raises(RuntimeError, match="invalid session group"):
        manager.create(CreatorSessionRequest("vk", "qwdtt", "managed", count=2))

    assert driver.rolled_back is True
