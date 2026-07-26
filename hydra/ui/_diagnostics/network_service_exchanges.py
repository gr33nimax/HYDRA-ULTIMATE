"""Multi-step network exchanges for service-region diagnostics."""
from __future__ import annotations

import json

from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
)


_DISNEY_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Content-Type": "application/json",
    "Authorization": (
        "Bearer "
        "ZGlzbmV5JmJyb3dzZXImMS4wLjA."
        "Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"
    ),
}


def _find_key_nested(value: object, target_key: str) -> object | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == target_key:
                return nested
            found = _find_key_nested(nested, target_key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_key_nested(nested, target_key)
            if found is not None:
                return found
    return None


def disney_region() -> str:
    """Complete Disney's device/token/session exchange and return its region."""
    operations = current_diagnostic_operations()
    device_body = json.dumps(
        {
            "deviceFamily": "browser",
            "applicationRuntime": "chrome",
            "deviceProfile": "windows",
            "attributes": {},
        },
    ).encode()
    device_response = operations.request(
        "https://disney.api.edge.bamgrid.com/devices",
        method="POST",
        headers=_DISNEY_HEADERS,
        data=device_body,
        timeout=3.0,
    )
    assertion = json.loads(device_response.text()).get("assertion")
    if not assertion:
        return "No"

    token_headers = {
        **_DISNEY_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    token_body = (
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3A"
        "token-exchange&latitude=0&longitude=0&platform=browser"
        f"&subject_token={assertion}"
        "&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3A"
        "token-type%3Adevice"
    ).encode()
    token_response = operations.request(
        "https://disney.api.edge.bamgrid.com/token",
        method="POST",
        headers=token_headers,
        data=token_body,
        timeout=3.0,
    )
    token_data = json.loads(token_response.text())
    refresh_token = token_data.get("refresh_token")
    access_token = token_data.get("access_token")
    if not refresh_token or not access_token:
        return "No"

    session_headers = {
        **_DISNEY_HEADERS,
        "Authorization": f"Bearer {access_token}",
    }
    session_body = json.dumps(
        {
            "query": (
                "mutation refreshToken($input: RefreshTokenInput!) {"
                " refreshToken(refreshToken: $input) {"
                " activeSession { sessionId } } }"
            ),
            "variables": {"input": {"refreshToken": refresh_token}},
        },
    ).encode()
    session_response = operations.request(
        "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
        method="POST",
        headers=session_headers,
        data=session_body,
        timeout=3.0,
    )
    region = _find_key_nested(
        json.loads(session_response.text()),
        "countryCode",
    )
    return str(region).upper() if region else "Yes"


__all__ = ["disney_region"]
