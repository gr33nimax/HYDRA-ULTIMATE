"""Disabling the last Naive user must never leave an unauthenticated proxy."""

from hydra.plugins.naive.configuration import render_caddyfile


def test_no_users_removes_forward_proxy_but_keeps_decoy(tmp_path):
    empty = render_caddyfile(
        domain="example.test",
        port=443,
        decoy_dir=tmp_path,
        log_dir=tmp_path,
        users=[],
    )
    permitted = render_caddyfile(
        domain="example.test",
        port=443,
        decoy_dir=tmp_path,
        log_dir=tmp_path,
        users=[{"username": "alice", "password": "test-password"}],
    )
    assert "    forward_proxy {" not in empty
    assert "file_server {" in empty
    assert "    forward_proxy {" in permitted
    assert "basic_auth alice test-password" in permitted
