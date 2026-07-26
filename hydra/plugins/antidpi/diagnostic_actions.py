"""Application-authorized AntiDPI diagnostic actions."""
from __future__ import annotations

from typing import Any

from hydra.core.state_models import AppState


class AntiDPIDiagnosticActionsMixin:
    """Keep concrete diagnostic imports inside the plugin adapter."""

    def run_selftest(
        self,
        *,
        state: AppState,
        output: str | None = None,
        wait_seconds: float = 2.0,
        full: bool = False,
        protocols: Any = None,
    ) -> dict:
        from hydra.plugins.antidpi.selftest import run_selftest

        return run_selftest(
            state,
            output,
            wait_seconds,
            full=full,
            protocols=protocols,
        )

    def capture_external_tests(
        self,
        *,
        state: AppState,
        output: str | None = None,
        seconds: float = 120.0,
    ) -> dict:
        from hydra.plugins.antidpi.selftest import capture_external_tests

        return capture_external_tests(
            state,
            output,
            seconds,
            runtime_snapshot=self.management_snapshot,
        )


__all__ = ["AntiDPIDiagnosticActionsMixin"]
