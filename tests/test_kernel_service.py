from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_kernel_models import KERNEL_HYDRACORE, KERNEL_SINGBOX_EXTENDED
from hydra.core.state_models import AppState
from hydra.services.kernel import KernelRuntimeStatus, KernelService
from hydra.services.kernel_infrastructure import KernelInfrastructure


class Prepared:
    def __init__(self, runtime: KernelRuntimeStatus) -> None:
        self.runtime = runtime
        self.committed = False
        self.rolled_back = False

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


class Runtime:
    def __init__(self) -> None:
        self.status = KernelRuntimeStatus(
            True,
            running=True,
            provider=KERNEL_SINGBOX_EXTENDED,
        )
        self.prepared: Prepared | None = None

    def inspect(self) -> KernelRuntimeStatus:
        return self.status

    def prepare_switch(self, provider: str, channel: str) -> Prepared:
        assert (provider, channel) == (KERNEL_HYDRACORE, "stable")
        self.status = KernelRuntimeStatus(
            True,
            running=True,
            provider=provider,
            capabilities=("hydracore", "call_vk_multi_user"),
        )
        self.prepared = Prepared(self.status)
        return self.prepared


def test_kernel_service_persists_only_after_verified_runtime() -> None:
    runtime = Runtime()
    saved: list[str] = []
    state = AppState()
    state.install.update({
        "singbox_last_update_check": "2026-08-10T00:00:00+00:00",
        "singbox_update_available": True,
        "singbox_latest_version": "v1.13.16-extended-hydracore.6",
    })
    service = KernelService(runtime, save_state=lambda current: saved.append(current.kernel.provider))

    result = service.switch(state, KERNEL_HYDRACORE)

    assert result.ok and result.changed
    assert state.kernel.provider == KERNEL_HYDRACORE
    assert saved == [KERNEL_HYDRACORE]
    assert runtime.prepared is not None and runtime.prepared.committed is True
    assert "singbox_last_update_check" not in state.install
    assert "singbox_update_available" not in state.install
    assert "singbox_latest_version" not in state.install


def test_kernel_service_rolls_runtime_back_when_state_save_fails() -> None:
    runtime = Runtime()
    state = AppState()
    state.install["singbox_update_available"] = True

    def fail_save(_state: AppState) -> None:
        _state.revision += 1
        raise OSError("disk full")

    state.revision = 7
    service = KernelService(runtime, save_state=fail_save)
    with pytest.raises(OSError, match="disk full"):
        service.switch(state, KERNEL_HYDRACORE)

    assert state.kernel.provider == KERNEL_SINGBOX_EXTENDED
    assert state.revision == 7
    assert state.install["singbox_update_available"] is True
    assert runtime.prepared is not None and runtime.prepared.rolled_back is True


def test_hydracore_contract_is_exact_and_does_not_accept_aliases() -> None:
    valid = {
        "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
        "features": {
            "call_vk_multi_user": True,
            "call_vk_adaptive_multipath": True,
            "call_vk_multi_user_client": False,
            "call_vk_multi_user_server": True,
            "call_vk_telemetry": True,
        },
        "protocols": {
            "call_modes": ["multi_user"],
            "call_vk_multi_user_wire": {"min": 3, "max": 3},
        },
    }
    alias = {
        "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
        "features": {"call_vk_multiuser": True},
        "protocols": {"call_modes": ["multi_user"]},
    }
    p2p_only = {
        "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
        "features": {
            "call_vk_multi_user": True,
            "call_vk_multi_user_client": False,
            "call_vk_multi_user_server": True,
        },
        "protocols": {
            "call_modes": ["p2p"],
            "call_vk_multi_user_wire": {"min": 3, "max": 3},
        },
    }

    assert KernelInfrastructure._has_hydracore_contract(valid) is True
    assert KernelInfrastructure._has_hydracore_debug_contract(valid) is True
    assert KernelInfrastructure._has_hydracore_contract(alias) is False
    assert KernelInfrastructure._has_hydracore_contract(p2p_only) is False
    assert "call_vk_multi_user" in KernelInfrastructure._normalized_capabilities(valid)
    assert "call_vk_multi_user" not in KernelInfrastructure._normalized_capabilities(alias)


def test_hydracore_debug_contract_requires_native_telemetry() -> None:
    payload = {
        "identity": {"core_id": "io.hydrabox.hydracore", "role": "vps"},
        "features": {
            "call_vk_multi_user": True,
            "call_vk_adaptive_multipath": True,
            "call_vk_multi_user_client": False,
            "call_vk_multi_user_server": True,
            "call_vk_telemetry": False,
        },
        "protocols": {
            "call_modes": ["multi_user"],
            "call_vk_multi_user_wire": {"min": 3, "max": 3},
        },
    }

    assert KernelInfrastructure._has_hydracore_contract(payload) is True
    assert KernelInfrastructure._has_hydracore_debug_contract(payload) is False


def test_kernel_service_rejects_stock_switch_before_mutating_active_calls() -> None:
    runtime = Runtime()
    state = AppState(protocols={
        "calls": SimpleNamespace(enabled=True),
    })
    state.kernel.provider = KERNEL_HYDRACORE
    service = KernelService(runtime, save_state=lambda _state: None)

    with pytest.raises(ValueError, match="disable or uninstall Calls"):
        service.switch(state, KERNEL_SINGBOX_EXTENDED)

    assert runtime.prepared is None
    assert state.kernel.provider == KERNEL_HYDRACORE


def test_kernel_probe_uses_runtime_legacy_dns_environment(tmp_path) -> None:
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    runtime = KernelInfrastructure(
        SimpleNamespace(run=run),
        config_path=tmp_path / "config.json",
        lock_path=tmp_path / "kernel.lock",
    )

    runtime._run(tmp_path / "sing-box", "check", "-c", str(tmp_path / "config.json"))

    env = calls[0][1]["env"]
    assert env["LEGACY_DNS_SERVERS"] == "true"
    assert env["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] == "true"
    assert env["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] == "true"


def test_kernel_candidate_error_redacts_secret_detail(tmp_path) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    runtime = KernelInfrastructure(
        HostBackend(),
        config_path=config,
        lock_path=tmp_path / "kernel.lock",
    )
    runtime._inspect_binary = lambda *_args, **_kwargs: KernelRuntimeStatus(
        True,
        provider=KERNEL_SINGBOX_EXTENDED,
    )
    runtime._run = lambda *_args: SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="invalid password=hunter2",
    )

    with pytest.raises(RuntimeError) as failure:
        runtime._validate_candidate(tmp_path / "sing-box", KERNEL_SINGBOX_EXTENDED)

    assert "hunter2" not in str(failure.value)
    assert str(failure.value) == "candidate rejected the active configuration"


class CopyFailHost(HostBackend):
    def __init__(self, candidate: Path, target: Path) -> None:
        super().__init__()
        self.candidate = candidate
        self.target = target

    def atomic_copy(self, source: Path, target: Path, *, mode=None) -> None:
        if source == self.candidate and target == self.target:
            raise OSError("replace failed")
        super().atomic_copy(source, target, mode=mode)


def test_kernel_replace_failure_restarts_previous_running_service(tmp_path) -> None:
    target = tmp_path / "sing-box"
    target.write_bytes(b"old")
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"new")
    host = CopyFailHost(candidate, target)
    events: list[str] = []
    singbox = SimpleNamespace(
        is_running=lambda: True,
        stop=lambda: events.append("stop") or True,
        start=lambda: events.append("start") or True,
        log=lambda *_args: None,
    )
    runtime = KernelInfrastructure(
        host,
        binary_path=target,
        config_path=tmp_path / "config.json",
        lock_path=tmp_path / "kernel.lock",
    )
    runtime._singbox = lambda: singbox
    runtime._download_candidate = lambda *_args: candidate
    runtime._validate_candidate = lambda *_args: KernelRuntimeStatus(
        True,
        provider=KERNEL_HYDRACORE,
        capabilities=("hydracore",),
    )

    with pytest.raises(OSError, match="replace failed"):
        runtime.prepare_switch(KERNEL_HYDRACORE, "stable")

    assert target.read_bytes() == b"old"
    assert events == ["stop", "start"]


def test_kernel_stop_failure_still_restarts_previous_running_service(tmp_path) -> None:
    target = tmp_path / "sing-box"
    target.write_bytes(b"old")
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"new")
    events: list[str] = []
    singbox = SimpleNamespace(
        is_running=lambda: True,
        stop=lambda: events.append("stop") or False,
        start=lambda: events.append("start") or True,
        log=lambda *_args: None,
    )
    runtime = KernelInfrastructure(
        HostBackend(),
        binary_path=target,
        config_path=tmp_path / "config.json",
        lock_path=tmp_path / "kernel.lock",
    )
    runtime._singbox = lambda: singbox
    runtime._download_candidate = lambda *_args: candidate
    runtime._validate_candidate = lambda *_args: KernelRuntimeStatus(
        True,
        provider=KERNEL_HYDRACORE,
        capabilities=("hydracore", "call_vk_multi_user"),
    )

    with pytest.raises(RuntimeError, match="failed to stop"):
        runtime.prepare_switch(KERNEL_HYDRACORE, "stable")

    assert target.read_bytes() == b"old"
    assert events == ["stop", "start"]
