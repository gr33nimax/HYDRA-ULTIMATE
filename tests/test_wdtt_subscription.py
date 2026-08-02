from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.wdtt.subscriptions import (
    activate_subscription,
    build_access_state,
)


TEST_JWE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


class _Host:
    def __init__(self, *, reload_ok: bool = True) -> None:
        self.reload_ok = reload_ok
        self.calls: list[list[object]] = []

    def atomic_write(
        self,
        path: Path,
        content: str | bytes,
        *,
        mode: int,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    @staticmethod
    def remove_file(path: Path, *, missing_ok: bool = True) -> None:
        path.unlink(missing_ok=missing_ok)

    def run(self, arguments, **_kwargs):
        self.calls.append(list(arguments))
        if arguments[0] == "pidof":
            return MagicMock(stdout="123\n", returncode=0)
        return MagicMock(
            stdout="",
            returncode=0 if self.reload_ok else 1,
        )


def _state(*, workers: int = 18, devices: int = 1) -> tuple[AppState, User]:
    user = User(
        email="alice@example.com",
        uuid="user-one",
        expiry_date="2030-01-01",
        hydrabox_jwe_key=TEST_JWE_KEY,
        devices={
            f"{index:064x}": {"source": "hydrabox"}
            for index in range(1, devices + 1)
        },
    )
    state = AppState(users=[user])
    state.network.server_ip = "203.0.113.10"
    state.protocols["wdtt"] = PluginState(
        enabled=True,
        config={"subscription_workers": workers},
    )
    return state, user


def _environment(tmp_path: Path, host: _Host) -> SimpleNamespace:
    headless_state = tmp_path / "headless" / "state.json"
    headless_state.parent.mkdir(parents=True)
    headless_state.write_text(
        json.dumps({"hashes": ["vk-a", "vk-b", "vk-c", "vk-d"]}),
        encoding="utf-8",
    )
    return SimpleNamespace(
        access_file=tmp_path / "hydra-access.json",
        headless_state_file=headless_state,
        headless_call_count=4,
        default_dtls_port=56000,
        json_module=json,
        host=host,
        local_ip=lambda: "203.0.113.10",
        public_ip=lambda: "203.0.113.10",
    )


def test_activation_returns_device_grant_but_persists_verifier_only(tmp_path):
    state, user = _state()
    device_id = next(iter(user.devices))
    env = _environment(tmp_path, _Host())

    first = activate_subscription(
        env,
        user=user,
        state=state,
        device_id=device_id,
    )
    second = activate_subscription(
        env,
        user=user,
        state=state,
        device_id=device_id,
    )

    credential = first["credentials"][0]
    endpoint = first["projection"]["endpoints"][0]
    durable = env.access_file.read_text(encoding="utf-8")
    access = json.loads(durable)
    assert second["credentials"] == first["credentials"]
    assert endpoint["credential_ref"] == credential["credential_ref"]
    assert endpoint["workers"] == 18
    assert "password" not in endpoint
    assert credential["device_grant"] not in durable
    assert access["credentials"][0]["token_sha256"]
    assert access["credentials"][0]["max_workers"] == 18
    assert access["credentials"][0]["max_burst_workers"] == 27
    assert access["max_total_workers"] == 27


def test_access_capacity_scales_with_devices_without_artificial_user_cap():
    state, _user = _state(devices=2)

    access = build_access_state(state)

    assert len(access["credentials"]) == 2
    assert access["max_total_workers"] == 54


def test_maximum_worker_policy_reserves_one_hot_rotation_group():
    state, _user = _state(workers=36)

    access = build_access_state(state)

    assert access["credentials"][0]["max_workers"] == 36
    assert access["credentials"][0]["max_burst_workers"] == 45
    assert access["max_total_workers"] == 45


def test_failed_hot_reload_restores_previous_access_file(tmp_path):
    state, user = _state()
    device_id = next(iter(user.devices))
    env = _environment(tmp_path, _Host(reload_ok=False))
    env.access_file.write_bytes(b"previous-access-state")

    with pytest.raises(RuntimeError, match="did not accept"):
        activate_subscription(
            env,
            user=user,
            state=state,
            device_id=device_id,
        )

    assert env.access_file.read_bytes() == b"previous-access-state"
