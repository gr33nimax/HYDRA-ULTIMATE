from __future__ import annotations

import copy
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.host import HOST, HostBackend
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.managed_nodes.observations import ManagedNodeObservationProvider
from hydra.services.managed_nodes.probe_clients import (
    ManagedNodeProbeClient,
    ManagedNodeProbeIdentityStore,
)


def material(**tls):
    return ProbeMaterial("vless", {
        "type": "vless", "tag": "vless-probe", "server": "203.0.113.4",
        "server_port": 443, "uuid": "technical-uuid", "tls": {"enabled": True, **tls},
    })


def test_status_sample_is_read_only_and_sync_write_uses_apply_lock():
    state = AppState(
        users=[User("one@example.test", "user-1")],
        protocols={"vless": PluginState(enabled=True)},
    )
    before = copy.deepcopy(state)
    locked = [False]
    writes = []
    runtime_reads = []
    counter_reads = []
    plugin = SimpleNamespace(meta=SimpleNamespace(name="vless", category=SimpleNamespace(value="transport")))

    def read_counters(_state, _name):
        counter_reads.append(locked[0])
        return {"one@example.test": 100}

    def observe_runtime():
        runtime_reads.append(locked[0])
        return {"engine_active": True, "runtime_id": "engine-1"}

    protocols = SimpleNamespace(
        list=lambda: [plugin], traffic_snapshot=read_counters,
        health=lambda _state, _name: True,
    )
    runtime = SimpleNamespace(
        observe=observe_runtime,
        metrics=lambda: {"cpu_percent": None, "ram_percent": None},
    )

    @contextmanager
    def mutation_lock():
        locked[0] = True
        try:
            yield
        finally:
            locked[0] = False

    def update(mutate):
        assert locked[0]
        writes.append("update_state")
        traffic = mutate(state)
        return copy.deepcopy(state), traffic

    observations = ManagedNodeObservationProvider(
        node_id="de-1", records=SimpleNamespace(list_operations=lambda: []),
        runtime=runtime, protocols=protocols, state_reader=lambda: copy.deepcopy(state),
        state_updater=update, mutation_lock=mutation_lock,
    )

    readonly_sample = observations.read()
    assert readonly_sample.traffic[0].used_bytes == 100
    assert state == before and writes == []
    assert runtime_reads == [False] and counter_reads == [False]
    committed_sample = observations.sync_sample()
    assert committed_sample.traffic[0].used_bytes == 100
    assert writes == ["update_state"] and not locked[0]
    assert runtime_reads == [False, True] and counter_reads == [False, True]
    assert state.install["managed_node_traffic_baselines"]["user-1:vless"]["runtime_id"] == "engine-1"


def test_probe_material_rejects_tls_bypass_options():
    with pytest.raises(ValueError, match="unsupported|TLS"):
        material(insecure=True).validate()


def test_probe_stops_process_before_removing_its_private_configuration(tmp_path: Path, monkeypatch):
    process = SimpleNamespace(stopped=False)

    class Process:
        def poll(self):
            return 0 if process.stopped else None

        def terminate(self):
            process.stopped = True

        def wait(self, timeout):
            return 0

        def kill(self):
            process.stopped = True

    class TestHost:
        def which(self, _name):
            return "sing-box"

        def atomic_write(self, path, content, **_kwargs):
            Path(path).write_text(content, encoding="utf-8")

        def run(self, _args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def popen(self, _args, **_kwargs):
            return Process()

        def remove_file(self, path, *, missing_ok=True):
            assert process.stopped
            Path(path).unlink(missing_ok=missing_ok)

    cleanup_state = {"stopped_before_cleanup": None}
    directory = tmp_path / "probe-private"
    original_rmtree = shutil.rmtree

    def remove_directory(path, *, ignore_errors=False):
        cleanup_state["stopped_before_cleanup"] = process.stopped
        original_rmtree(path, ignore_errors=ignore_errors)

    monkeypatch.setattr("hydra.services.managed_nodes.probe_clients.tempfile.mkdtemp", lambda **_kwargs: (directory.mkdir(), str(directory))[1])
    monkeypatch.setattr("hydra.services.managed_nodes.probe_clients.shutil.rmtree", remove_directory)
    monkeypatch.setattr(ManagedNodeProbeClient, "_wait_listener", staticmethod(lambda *_args: False))
    client = ManagedNodeProbeClient(host=cast(HostBackend, TestHost()))

    result = client._run_client(material(), node_id="de-1", binary="sing-box", deadline=time.monotonic() + 1, checked_at="now")

    assert result.outcome == "error"
    assert cleanup_state["stopped_before_cleanup"] is True
    assert process.stopped is True
    assert not directory.exists()


def test_probe_identity_is_protected_and_not_inserted_into_business_state(tmp_path: Path):
    modes = {}

    class ProtectedHost:
        def ensure_directory(self, *args, **kwargs):
            HOST.ensure_directory(*args, **kwargs)

        def atomic_write(self, path, content, *, mode, durable):
            modes[Path(path)] = mode
            HOST.atomic_write(path, content, mode=mode, durable=durable)

        def read_bytes(self, *args, **kwargs):
            return HOST.read_bytes(*args, **kwargs)

        def remove_file(self, *args, **kwargs):
            HOST.remove_file(*args, **kwargs)

    identity_root = tmp_path / "identity"
    store = ManagedNodeProbeIdentityStore(host=cast(HostBackend, ProtectedHost()), root=identity_root, node_id="de-1")
    technical_user = store.ensure()
    identity_path = identity_root / "probe-identity.json"

    assert modes[identity_path] == 0o600
    assert technical_user.uuid
    assert AppState().users == []
    store.cleanup()
    assert not identity_path.exists()
