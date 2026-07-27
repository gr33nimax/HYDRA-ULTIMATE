"""Administrative AntiDPI operations over explicit state/runtime ports."""
from __future__ import annotations

import ipaddress

from hydra.plugins.antidpi.model import (
    active_bans,
    expire_bans,
    record_manual_ban,
    record_unban,
)
from hydra.plugins.antidpi.firewall_rules import SET_V4, SET_V6
from hydra.plugins.antidpi.projection import management_projection
from hydra.plugins.context import PluginStateAccess


class AntiDPIManagementMixin:
    """Keep CRUD-style management out of the plugin lifecycle facade."""

    def _load_state(self) -> dict:
        """Compatibility wrapper; new consumers use ``management_snapshot``."""
        return self._state_store().load()

    def _save_state(self, data: dict) -> None:
        self._state_store().save(data)

    def management_snapshot(self) -> dict:
        """Return bounded detector evidence without mutating runtime state."""
        with self._state_lock():
            data = self._state_store().load()
        return management_projection(data, now=self._clock())

    def recent_logs(self, *, limit: int = 50) -> list[str]:
        result = self._command(
            [
                "journalctl",
                "-u",
                "hydra-antidpi",
                "-n",
                str(max(1, min(int(limit), 200))),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            text=True,
        )
        output = str(
            getattr(result, "stdout", "")
            or getattr(result, "stderr", "")
            or "",
        ).strip()
        return output.splitlines()

    def add_whitelist(
        self,
        *,
        state: PluginStateAccess,
        network: str,
    ) -> bool:
        del state
        parsed = ipaddress.ip_network(network, strict=False)
        normalized = str(parsed)
        with self._state_lock():
            data = self._state_store().load()
            values = data.get("whitelist", [])
            if not isinstance(values, list):
                values = []
            already_present = normalized in values
            if not already_present:
                values.append(normalized)
                data["whitelist"] = values
                self._state_store().save(data)
            covered = self._banned_inside(data, parsed, now=self._clock())
        # Releasing runs outside the state lock: ``unban`` acquires it again
        # and flock is not reentrant across file descriptors.
        for address in covered:
            self.unban(address)
        return not already_present

    @staticmethod
    def _banned_inside(
        data: dict,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        *,
        now: float,
    ) -> list[str]:
        """Return active bans that a newly trusted network now covers."""
        matches = []
        for address in active_bans(data, now=now):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.version == network.version and parsed in network:
                matches.append(address)
        return sorted(matches)

    def remove_whitelist(
        self,
        *,
        state: PluginStateAccess,
        network: str,
    ) -> bool:
        del state
        normalized = str(ipaddress.ip_network(network, strict=False))
        with self._state_lock():
            data = self._state_store().load()
            values = data.get("whitelist", [])
            if not isinstance(values, list) or normalized not in values:
                return False
            values.remove(normalized)
            data["whitelist"] = values
            self._state_store().save(data)
        return True

    def unban_address(
        self,
        *,
        state: PluginStateAccess,
        address: str,
    ) -> bool:
        del state
        return self.unban(address)

    def cleanup_honeypot_duplicates(self) -> int:
        """Drop AntiDPI ownership for addresses already owned by Honeypot."""
        try:
            honeypot_bans = set(self._honeypot_bans())
        except Exception:
            return 0
        antidpi_bans = set(active_bans(self._state_store().load()))
        removed = 0
        for address in sorted(antidpi_bans & honeypot_bans):
            if self.unban(address):
                removed += 1
        return removed

    def unban(self, raw: str) -> bool:
        """Remove an address from ipset and persistent evidence."""
        try:
            address = ipaddress.ip_address(str(raw).strip("[]"))
        except ValueError:
            return False
        name = SET_V6 if address.version == 6 else SET_V4
        result = self._command(
            ["ipset", "del", name, address.compressed],
            text=True,
        )
        detail = str(
            getattr(result, "stderr", "")
            or getattr(result, "stdout", "")
            or "",
        ).lower()
        if getattr(result, "returncode", 1) != 0 and "not in set" not in detail:
            return False
        with self._state_lock():
            data = self._state_store().load()
            record_unban(data, address.compressed, now=self._clock())
            self._state_store().save(data)
        return True

    def manual_ban(self, raw: str, *, source: str = "manual") -> dict:
        """Permanently block an address until an administrator unbans it."""
        try:
            address = ipaddress.ip_address(str(raw).strip().strip("[]"))
        except ValueError:
            return {"ok": False, "error": "invalid_ip"}
        if not self._ensure_sets() or not self._ensure_rules():
            return {"ok": False, "error": "firewall_error"}
        timestamp = self._clock()
        compressed = address.compressed
        with self._state_lock():
            data = self._state_store().load()
            if self._is_whitelisted(address, data):
                return {"ok": False, "error": "whitelisted"}
            expire_bans(data, now=timestamp)
            current = active_bans(data, now=timestamp).get(compressed)
            if isinstance(current, dict) and current.get("permanent") is True:
                return {
                    "ok": True,
                    "already_active": True,
                    "remaining": 0,
                    **current,
                }
            if not self._add_firewall_ban(address, duration=0):
                return {"ok": False, "error": "firewall_error"}
            metadata = record_manual_ban(
                data,
                compressed,
                source=source,
                timestamp=timestamp,
                current=current if isinstance(current, dict) else None,
            )
            self._state_store().save(data)
            return {"ok": True, "already_active": False, **metadata}

    def sync_host_whitelist(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[str]:
        """Persist every known VPS address in the AntiDPI whitelist."""
        configured = state.network.server_ip if state is not None else ""
        addresses = list(self._host_addresses((configured,)))
        with self._state_lock():
            data = self._state_store().load()
            values = data.get("whitelist", [])
            if not isinstance(values, list):
                values = []
            changed = False
            for address in addresses:
                if address not in values:
                    values.append(address)
                    changed = True
            data["whitelist"] = values
            if changed:
                self._state_store().save(data)
        return addresses
