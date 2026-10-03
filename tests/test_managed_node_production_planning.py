from subprocess import CompletedProcess
from typing import cast

import pytest

from hydra import bootstrap
from hydra.core.host import HostBackend
from hydra.core import state as state_backend
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.records import ManagedNodeRecords
from tests.test_managed_node_enrollment import StrictSsh, request

_SHA = "a" * 40


@pytest.mark.parametrize("branch", ["main", "dev"])
def test_production_planner_binds_repository_without_replacing_selected_branch(monkeypatch, tmp_path, branch):
    calls = []

    class RevisionHost:
        def run(self, args, *, timeout, text):
            calls.append((args, timeout, text))
            assert args == [
                "git",
                "ls-remote",
                "--exit-code",
                bootstrap._MANAGED_NODE_REPOSITORY,
                f"refs/heads/{branch}",
            ]
            return CompletedProcess(args, 0, f"{_SHA}\trefs/heads/{branch}\n", "")

    host = cast(HostBackend, RevisionHost())
    remote = StrictSsh()
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    credentials = ManagementCredentialStore(host=host, root=tmp_path / "credentials")
    monkeypatch.setattr(bootstrap, "HOST", host)
    monkeypatch.setattr(bootstrap, "OpenSshManagedNodeSSH", lambda **_kwargs: remote)
    operations = bootstrap.production_managed_node_operations(records=records, credentials=credentials)
    before = state_backend.load_state()

    plan = operations.plan(request(branch=branch, control_port=25555), ssh_auth=None)

    assert plan.definition.branch == branch
    assert plan.definition.revision == _SHA
    assert len(calls) == 1 and calls[0][1:] == (20, True)
    assert remote.calls == ["inspect"]
    assert records.list_definitions() == []
    assert state_backend.load_state() == before
    assert not (tmp_path / "credentials").exists()
