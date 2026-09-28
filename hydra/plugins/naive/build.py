"""Binary build selection for NaiveProxy: which module, and how to prove it."""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .constants import NaiveRuntimeLayout
from .uot import build_module, write_probe


if TYPE_CHECKING:
    _RuntimeLayout = Callable[[], NaiveRuntimeLayout]
    _HostBackend = Callable[[], Any]
    _ValidateCaddy = Callable[..., str | None]


class NaiveBuildMixin:
    """Build the Caddy binary for a UoT mode without guessing what is installed."""

    if TYPE_CHECKING:
        _runtime_layout: _RuntimeLayout
        _host_backend: _HostBackend
        _validate_caddy: _ValidateCaddy

    def _built_for_uot(self) -> bool | None:
        """The installed build's UoT capability, or None while no binary is installed."""
        layout = self._runtime_layout()
        if not layout.binary.is_file():
            return None
        with tempfile.TemporaryDirectory(prefix="hydra-naive-probe-") as directory:
            probe = Path(directory) / "Caddyfile"
            write_probe(probe, True)
            return not self._validate_caddy(probe, binary=layout.binary)

    def _download_binary(
        self,
        config_path: Path | None = None,
        *,
        uot: bool = True,
    ) -> bool:
        from hydra.core import sni_router, sni_router_install

        host = self._host_backend()
        layout = self._runtime_layout()
        settings = replace(
            sni_router._install_settings(),
            binary=layout.binary,
            caddy_version="v2.10.2",
        )
        existed = layout.binary.exists()
        layout.binary.parent.mkdir(parents=True, exist_ok=True)
        print(f"  Собираю caddy-naive {'с поддержкой UoT' if uot else 'без UoT'}...")
        with tempfile.TemporaryDirectory(prefix="hydra-naive-") as directory:
            probe = Path(directory) / "Caddyfile"
            write_probe(probe, uot)
            success = sni_router_install.install(
                None,
                settings,
                host,
                force=True,
                installed=lambda: False,
                forward_proxy=True,
                forward_proxy_module=build_module(uot),
                layer4=False,
                ensure_go=lambda: sni_router_install.ensure_modern_go(
                    settings,
                    host,
                    official_digest=sni_router._official_go_digest,
                ),
                build=lambda args, env: sni_router_install.run_caddy_build(
                    args,
                    env,
                    host=host,
                    timeout=settings.build_timeout,
                ),
                validate=lambda binary: (
                    not self._validate_caddy(
                        config_path or probe,
                        binary=binary,
                    )
                ),
            )
        if success and existed:
            self._binary_replaced = True
        return success
