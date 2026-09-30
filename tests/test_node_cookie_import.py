import io
import json
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_nodes import NodeConfig
from hydra.entrypoints import node_cookies
from hydra.services.headless_creator_infrastructure import HeadlessCreatorInfrastructure
from hydra.services.nodes.cookies import MAX_NODE_COOKIE_BYTES, import_node_vk_cookies


SECRET = "private-vk-session-value"


def _source(tmp_path):
    source = tmp_path / "node-cookies.json"
    source.write_text(json.dumps([{"name": "remixsid", "value": SECRET}]), encoding="utf-8")
    root = tmp_path / "ssh"
    pin = root / "de-1" / "known_hosts"
    pin.parent.mkdir(parents=True)
    pin.write_text("pinned-key", encoding="utf-8")
    return source, root


def test_upload_streams_only_to_selected_pinned_node_without_tty_or_argv_secrets(tmp_path, monkeypatch):
    source, root = _source(tmp_path)
    host = HostBackend()
    run = Mock(return_value=CompletedProcess([], 0, stdout="", stderr=""))
    monkeypatch.setattr(host, "run", run)
    node = NodeConfig(id="de-1", address="node.example.com", ssh_port=2222)
    import_node_vk_cookies(node, str(source), host=host, known_hosts_root=root)
    argv = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert argv[:2] == ["ssh", "-T"]
    assert "-tt" not in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "root@node.example.com" in argv
    assert "2222" in argv
    assert SECRET not in " ".join(argv)
    assert str(source) not in " ".join(argv)
    assert json.loads(kwargs["input"]) == {
        "node_id": "de-1", "cookies": [{"name": "remixsid", "value": SECRET}],
    }
    assert kwargs["timeout"] == 180
    assert kwargs["capture_output"] is True


@pytest.mark.parametrize("failure", ["untrusted", "invalid", "oversize"])
def test_invalid_upload_is_rejected_before_ssh(tmp_path, monkeypatch, failure):
    source, root = _source(tmp_path)
    if failure == "untrusted":
        (root / "de-1" / "known_hosts").unlink()
    elif failure == "invalid":
        source.write_text("{}", encoding="utf-8")
    else:
        source.write_bytes(b"x" * (MAX_NODE_COOKIE_BYTES + 1))
    host = HostBackend()
    run = Mock()
    monkeypatch.setattr(host, "run", run)
    with pytest.raises((RuntimeError, ValueError)):
        import_node_vk_cookies(NodeConfig(id="de-1", address="node.example.com"), str(source), host=host, known_hosts_root=root)
    run.assert_not_called()


def test_remote_import_failure_does_not_return_secret_stderr(tmp_path, monkeypatch):
    source, root = _source(tmp_path)
    host = HostBackend()
    monkeypatch.setattr(host, "run", Mock(return_value=CompletedProcess([], 2, stdout=SECRET, stderr=SECRET)))
    with pytest.raises(RuntimeError) as caught:
        import_node_vk_cookies(NodeConfig(id="de-1", address="node.example.com"), str(source), host=host, known_hosts_root=root)
    assert SECRET not in str(caught.value)


def _entrypoint(monkeypatch, document, identity="de-1"):
    monkeypatch.setattr(node_cookies, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    monkeypatch.setattr(node_cookies, "load_node_identity", lambda: SimpleNamespace(node_id=identity) if identity else None)
    monkeypatch.setattr(node_cookies.sys, "stdin", io.StringIO(json.dumps(document)))
    importer = Mock()
    monkeypatch.setattr(node_cookies, "production_node_cookie_import", importer)
    return importer


def test_node_import_is_identity_scoped_and_does_not_apply_or_create_rooms(monkeypatch, capsys):
    importer = _entrypoint(monkeypatch, {"node_id": "de-1", "cookies": [{"name": "remixsid", "value": SECRET}]})
    assert node_cookies.main() == 0
    importer.assert_called_once_with([{"name": "remixsid", "value": SECRET}])
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize("identity", [None, "other-node"])
def test_wrong_or_missing_identity_never_imports_credentials(monkeypatch, identity, capsys):
    importer = _entrypoint(monkeypatch, {"node_id": "de-1", "cookies": [{"name": "remixsid", "value": SECRET}]}, identity)
    assert node_cookies.main() == 2
    importer.assert_not_called()
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


def test_import_rejects_unknown_request_fields(monkeypatch):
    importer = _entrypoint(monkeypatch, {"node_id": "de-1", "cookies": [{"name": "sid", "value": SECRET}], "path": "/etc/other"})
    assert node_cookies.main() == 2
    importer.assert_not_called()


def test_document_import_is_atomic_validated_and_does_not_start_pool(tmp_path, monkeypatch):
    host = HostBackend()
    run = Mock(side_effect=AssertionError("cookie import cannot invoke systemd or creator"))
    monkeypatch.setattr(host, "run", run)
    runtime = HeadlessCreatorInfrastructure(host, cookies_file=tmp_path / "node" / "cookies.json")
    runtime.import_vk_cookie_document([{"name": "sid", "value": SECRET}])
    assert json.loads(runtime.cookies_file.read_text()) == [{"name": "sid", "value": SECRET}]
    before = runtime.cookies_file.read_bytes()
    with pytest.raises(ValueError):
        runtime.import_vk_cookie_document([{"name": "sid", "value": ""}])
    assert runtime.cookies_file.read_bytes() == before
    run.assert_not_called()
