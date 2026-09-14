from email.message import Message
from typing import cast
from urllib.error import HTTPError

from hydra.services.vk_turn_probe import VkTurnProbe


def _responses():
    return iter(
        [
            {"response": {"token": "vk-token"}},
            {"response": {"user_id": 7, "secret": "secret"}},
            {"response": {"token": "ok-token"}},
            {"session_key": "session"},
            {"turn_server": {"username": "user", "credential": "password", "urls": ["turn:example"]}},
        ]
    )


def test_turn_probe_requires_complete_turn_credentials() -> None:
    responses = _responses()

    def post(_url: str) -> dict[str, object]:
        return cast(dict[str, object], next(responses))

    assert VkTurnProbe(post=post).verify("https://vk.com/call/join/room").outcome == "healthy"


def test_turn_probe_classifies_call_unavailable_as_dead() -> None:
    result = VkTurnProbe(post=lambda _url: {"error": {"error_code": 951}}).verify("https://vk.com/call/join/room")

    assert result.outcome == "dead"


def test_turn_probe_classifies_http_rate_limit_without_eviction() -> None:
    def rate_limited(_url: str) -> dict[str, object]:
        raise HTTPError(_url, 429, "too many requests", Message(), None)

    assert VkTurnProbe(post=rate_limited).verify("https://vk.com/call/join/room").outcome == "rate_limited"


def test_turn_probe_does_not_treat_captcha_as_dead() -> None:
    result = VkTurnProbe(post=lambda _url: {"error": {"error_code": 14}}).verify("https://vk.com/call/join/room")

    assert result.outcome == "captcha"
