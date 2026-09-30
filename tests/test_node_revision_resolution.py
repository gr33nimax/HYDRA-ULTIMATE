import json
import urllib.error
from typing import cast
from unittest.mock import Mock, patch

import pytest

from hydra.services.nodes.bootstrap import NodeBootstrap
from hydra.services.nodes.manager import NodeManager


SHA = "a" * 40


def _payload(branch="dev", sha=SHA, kind="commit"):
    return json.dumps({"ref": f"refs/heads/{branch}", "object": {"type": kind, "sha": sha}}).encode()


def _bootstrap():
    return NodeBootstrap(host=Mock(), script="#!/bin/bash\nexit 0\n")


def test_resolve_branch_uses_bounded_https_and_no_credentials(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-send")
    response = Mock()
    response.read.return_value = _payload("feature/nodes")
    with patch("urllib.request.urlopen") as get:
        get.return_value.__enter__.return_value = response
        bootstrap = _bootstrap()
        assert bootstrap.resolve_revision("feature/nodes") == SHA
    request = get.call_args.args[0]
    assert request.full_url == "https://api.github.com/repos/gr33nimax/HYDRA-ULTIMATE/git/ref/heads/feature%2Fnodes"
    assert "Authorization" not in request.headers
    assert get.call_args.kwargs["timeout"] == 10
    assert response.read.call_args.args[0] <= 65537
    cast(Mock, bootstrap.host).run.assert_not_called()


@pytest.mark.parametrize("payload", [b"invalid-json", b"[]", _payload("other"), _payload(sha="short"), _payload(kind="blob"), b"x" * 65537], ids=["json", "object", "wrong-ref", "short-sha", "blob", "oversize"])
def test_invalid_revision_response_fails_closed_without_host_access(payload):
    response = Mock()
    response.read.return_value = payload
    bootstrap = _bootstrap()
    with patch("urllib.request.urlopen") as get:
        get.return_value.__enter__.return_value = response
        with pytest.raises(ValueError):
            bootstrap.resolve_revision("dev")
    cast(Mock, bootstrap.host).run.assert_not_called()


def test_network_error_is_sanitized_and_does_not_install():
    bootstrap = _bootstrap()
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("secret-proxy-password")):
        with pytest.raises(ValueError) as raised:
            bootstrap.resolve_revision("dev")
    assert "secret-proxy-password" not in str(raised.value)
    cast(Mock, bootstrap.host).run.assert_not_called()


def test_unsafe_branch_is_rejected_before_network():
    with patch("urllib.request.urlopen") as get:
        with pytest.raises(ValueError):
            _bootstrap().resolve_revision("../bad")
    get.assert_not_called()


def test_manager_revision_resolution_is_injected_read_only_and_validated():
    bootstrap = Mock()
    bootstrap.resolve_revision.return_value = SHA
    state_reader, state_updater, client_for = Mock(), Mock(), Mock()
    manager = NodeManager(state_reader=state_reader, state_updater=state_updater, client_for=client_for, snapshot_store=Mock(), bootstrap=bootstrap)
    assert manager.resolve_revision("dev") == SHA
    bootstrap.resolve_revision.assert_called_once_with("dev")
    state_reader.assert_not_called()
    state_updater.assert_not_called()
    client_for.assert_not_called()
    bootstrap.install.assert_not_called()
    bootstrap.resolve_revision.return_value = "bad"
    with pytest.raises(ValueError):
        manager.resolve_revision("dev")
