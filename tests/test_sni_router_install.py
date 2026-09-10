"""Caddy L4 installer tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hydra.core.sni_router_install import InstallSettings, install


def test_naive_build_uses_the_uot_fork_without_fallback(tmp_path: Path) -> None:
    binary = tmp_path / "caddy-l4"
    builds: list[list[str]] = []

    def build(args: list[str], _env: dict[str, str]) -> SimpleNamespace:
        builds.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="failed")

    settings = InstallSettings(
        binary=binary,
        caddy_l4_version="v2.0.0",
        go_version="1.25.0",
        go_releases_url="",
        build_timeout=1,
    )
    state = SimpleNamespace(
        protocols={"naive": SimpleNamespace(enabled=True)},
    )
    with patch(
        "hydra.core.sni_router_install._ensure_xcaddy_binary",
        return_value="xcaddy",
    ):
        assert not install(
            state,
            settings,
            SimpleNamespace(),
            force=True,
            installed=lambda: False,
            ensure_go=lambda: True,
            build=build,
        )

    assert len(builds) == 1
    assert (
        "github.com/caddyserver/forwardproxy@caddy2="
        "github.com/aUsernameWoW/forwardproxy@naive"
    ) in builds[0]
