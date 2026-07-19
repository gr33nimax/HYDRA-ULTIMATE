import json
from types import SimpleNamespace

import pytest

from hydra import cli
from hydra.core.errors import ErrorCode, HostOperationError
from hydra.core.host import HostBackend
from hydra.core.state import AppState
from hydra.services.application import ApplicationService


def test_application_apply_result_maps_host_failure_to_retryable_error():
    app = ApplicationService(
        users=SimpleNamespace(), protocols=SimpleNamespace(),
        apply_config=lambda state: (_ for _ in ()).throw(HostOperationError("systemd unavailable")),
        last_apply_error=lambda: "",
    )

    result = app.apply_result(AppState())

    assert not result
    assert result.error.code is ErrorCode.HOST_OPERATION
    assert result.error.retryable is True


def test_application_user_result_does_not_hide_lifecycle_exception():
    class Users:
        def block(self, state, email):
            raise HostOperationError("iptables unavailable")

    app = ApplicationService(
        users=Users(), protocols=SimpleNamespace(),
        apply_config=lambda state: True, last_apply_error=lambda: "",
    )

    result = app.user_result("block", AppState(), "alice@example.com")

    assert not result
    assert result.error.code is ErrorCode.HOST_OPERATION
    assert "iptables" in result.error.message


def test_cli_error_payload_contains_legacy_message_and_structured_details(capsys):
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli, "load_state", lambda: AppState())
        patch.setattr(cli, "_require_root", lambda: None)
        assert cli.main(["restore", "/tmp/archive.tar.gz"]) == 1

    payload = json.loads(capsys.readouterr().out)
    assert "restore requires --yes" in payload["error"]
    assert payload["error_details"]["code"] == "invalid_input"


def test_update_state_does_not_persist_when_mutator_fails(tmp_path):
    import hydra.core.state as state_mod

    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_DIR = tmp_path
        state_mod.STATE_FILE = tmp_path / "state.json"
        state_mod.save_state(AppState(install={"stable": True}))

        def fail(current):
            current.install["stable"] = False
            raise RuntimeError("mutator failed")

        with pytest.raises(RuntimeError, match="mutator failed"):
            state_mod.update_state(fail)
        assert state_mod.load_state().install["stable"] is True
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir


def test_host_persist_firewall_fails_closed_when_snapshot_command_fails(monkeypatch):
    host = HostBackend()
    monkeypatch.setattr(host, "which", lambda name: None)
    monkeypatch.setattr(
        host, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
    )

    assert host.persist_firewall() is False


def test_result_payload_omits_success_error_details():
    app = ApplicationService(
        users=SimpleNamespace(), protocols=SimpleNamespace(),
        apply_config=lambda state: True, last_apply_error=lambda: "stale error",
    )
    result = app.apply_result(AppState())

    assert result.as_dict() == {"ok": True, "value": True}
