"""Bounded anonymous VK/OK CDN proof that a Calls room issues TURN credentials."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from hydra.services.calls_health import ProbeOutcome

VK_API = "https://api.vk.me/method/"
OK_API = "https://calls.okcdn.ru/fb.do"
VK_CLIENT_ID = "8093730"  # User-approved public anonymous client identifier.
OK_APPLICATION_KEY = "CGMMEJLGDIHBABABA"  # User-approved public application key.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36"


@dataclass(frozen=True)
class VkTurnProbeResult:
    outcome: ProbeOutcome


@dataclass
class VkTurnProbe:
    """Perform no retries and never return API values that may be secrets."""

    post: Callable[[str], dict[str, object]] | None = None

    def verify(self, join_link: str) -> VkTurnProbeResult:
        try:
            post = self.post or _post_json
            device_id = str(uuid4())
            common = {"v": "5.276", "client_id": VK_CLIENT_ID, "device_id": device_id, "lang": "en"}
            anonymous = self._vk(
                post,
                "auth.getAnonymToken",
                {
                    **common,
                    "link": join_link,
                    "anonymName": "Hydra",
                },
            )
            token = _string(anonymous, "response", "token")
            preview = self._vk(
                post,
                "messages.getCallPreview",
                {
                    "v": common["v"],
                    "anonymous_token": token,
                    "device_id": device_id,
                    "extended": "1",
                    "fields": "first_name,last_name,photo_200",
                    "lang": "en",
                    "link": join_link,
                },
            )
            _raise_vk_error(preview)
            user_id = _number(preview, "response", "user_id")
            secret = _string(preview, "response", "secret")
            call_token = self._vk(
                post,
                "messages.getAnonymCallToken",
                {
                    "v": common["v"],
                    "anonymous_token": token,
                    "device_id": device_id,
                    "link": join_link,
                    "name": "Hydra",
                    "user_id": str(user_id),
                    "secret": secret,
                    "lang": "en",
                },
            )
            _raise_vk_error(call_token)
            ok_token = _string(call_token, "response", "token")
            session = post(
                _url(
                    OK_API,
                    {
                        "method": "auth.anonymLogin",
                        "format": "JSON",
                        "application_key": OK_APPLICATION_KEY,
                        "session_data": json.dumps(
                            {"version": 2, "device_id": str(uuid4()), "client_version": "1.0.1"}
                        ),
                    },
                )
            )
            session_key = _string(session, "session_key")
            turn = post(
                _url(
                    OK_API,
                    {
                        "method": "vchat.joinConversationByLink",
                        "format": "JSON",
                        "application_key": OK_APPLICATION_KEY,
                        "joinLink": join_link.rsplit("/", 1)[-1],
                        "isVideo": "false",
                        "protocolVersion": "5",
                        "anonymToken": ok_token,
                        "session_key": session_key,
                    },
                )
            )
            _raise_ok_error(turn)
            if not (
                _string(turn, "turn_server", "username")
                and _string(turn, "turn_server", "credential")
                and _strings(turn, "turn_server", "urls")
            ):
                raise ValueError("TURN response is incomplete")
            return VkTurnProbeResult("healthy")
        except _ProbeFailure as failure:
            return VkTurnProbeResult(failure.outcome)
        except HTTPError as failure:
            return VkTurnProbeResult("rate_limited" if failure.code == 429 else "error")
        except (URLError, OSError, TimeoutError):
            return VkTurnProbeResult("network")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return VkTurnProbeResult("error")

    @staticmethod
    def _vk(post: Callable[[str], dict[str, object]], method: str, params: dict[str, str]) -> dict[str, object]:
        response = post(_url(VK_API + method, params))
        _raise_vk_error(response)
        return response


@dataclass(frozen=True)
class _ProbeFailure(Exception):
    outcome: ProbeOutcome


def _post_json(url: str) -> dict[str, object]:
    request = Request(url, method="POST", headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(request, timeout=20) as response:  # nosec B310: fixed provider endpoints above
        try:
            payload = json.loads(response.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("provider returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("provider returned a non-object JSON response")
    return payload


def _url(endpoint: str, params: dict[str, str]) -> str:
    return endpoint + "?" + urlencode(params)


def _nested(value: dict[str, object], *keys: str) -> object:
    current: object = value
    for key in keys:
        if not isinstance(current, dict):
            raise ValueError("provider response is malformed")
        current = current[key]
    return current


def _string(value: dict[str, object], *keys: str) -> str:
    result = _nested(value, *keys)
    if not isinstance(result, str) or not result:
        raise ValueError("provider response is missing a string")
    return result


def _number(value: dict[str, object], *keys: str) -> int:
    result = _nested(value, *keys)
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ValueError("provider response is missing a number")
    try:
        return int(result)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("provider response has an invalid number") from exc


def _strings(value: dict[str, object], *keys: str) -> list[str]:
    result = _nested(value, *keys)
    if not isinstance(result, list) or not result or not all(isinstance(item, str) and item for item in result):
        raise ValueError("provider response is missing TURN URLs")
    return result


def _error_code(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value) if isinstance(value, (int, float, str)) else 0
    except ValueError:
        return 0


def _raise_vk_error(value: dict[str, object]) -> None:
    error = value.get("error")
    if not isinstance(error, dict):
        return
    code = _error_code(error.get("error_code"))
    if code == 14:
        raise _ProbeFailure("captcha")
    if code in {6, 29}:
        raise _ProbeFailure("rate_limited")
    if code in {951, 954} or 9000 <= code <= 9999:
        raise _ProbeFailure("dead")
    raise _ProbeFailure("error")


def _raise_ok_error(value: dict[str, object]) -> None:
    code = _error_code(value.get("error_code"))
    if code:
        raise _ProbeFailure("dead" if code in {951, 954} else "error")
