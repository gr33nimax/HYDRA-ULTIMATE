"""Transactional desired-state command for upstream AWG generation changes."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hydra.plugins.context import PluginStateAccess

from .directives import AwgDirectiveError, AwgInterfaceDirectives, canonical_mode


class AwgProtocolModeMixin:
    """Keep desired mode aligned with a verified upstream runtime mode."""

    if TYPE_CHECKING:

        def observed_protocol_mode(self) -> str: ...

        def migrate_protocol_mode(
            self,
            mode: object,
            state: PluginStateAccess | None = None,
        ) -> None: ...

        def _conf_path(self, profile_name: str) -> Path: ...

        def export_capabilities(self, state: PluginStateAccess) -> dict[str, str]: ...

    @staticmethod
    def desired_protocol_mode(state: PluginStateAccess) -> str:
        protocol = state.protocols.get("amneziawg")
        raw = protocol.config.get("protocol_mode", "2.0") if protocol else "2.0"
        return canonical_mode(raw)

    def protocol_mode_status(self, state: PluginStateAccess) -> dict[str, object]:
        """Return a redacted mode and export-capability projection."""
        desired = self.desired_protocol_mode(state)
        try:
            observed = self.observed_protocol_mode()
        except RuntimeError:
            observed = "unavailable"
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        desktop = profiles.get("desktop") if isinstance(profiles, dict) else None
        legacy_strategy = desktop.get("preset", "custom") if isinstance(desktop, dict) else "custom"
        return {
            "desired": desired,
            "observed": observed,
            "legacy_strategy": legacy_strategy,
            "exports": self.export_capabilities(state),
        }

    def set_protocol_mode(self, state: PluginStateAccess, mode: object) -> bool:
        """Migrate upstream first; persist desired mode only after verification."""
        protocol = state.protocols.get("amneziawg")
        if protocol is None or not protocol.installed:
            raise RuntimeError("AmneziaWG is not installed")
        target = canonical_mode(mode)
        desired = self.desired_protocol_mode(state)
        observed = self.observed_protocol_mode()
        if desired == target and observed == target:
            return False
        if observed != target:
            self.migrate_protocol_mode(target, state)
        if self.observed_protocol_mode() != target:
            raise RuntimeError("AmneziaWG protocol migration did not reach requested mode")
        conf_path = self._conf_path("desktop")
        if not conf_path.exists():
            raise RuntimeError("AmneziaWG primary configuration is missing")
        try:
            AwgInterfaceDirectives.parse(conf_path.read_text(encoding="utf-8")).for_mode(target)
        except AwgDirectiveError as exc:
            raise RuntimeError("AmneziaWG migrated configuration is invalid") from exc
        protocol.config["protocol_mode"] = target
        return True
