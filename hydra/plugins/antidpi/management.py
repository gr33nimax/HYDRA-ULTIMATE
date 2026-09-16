"""Administrative AntiDPI operations over explicit state/runtime ports."""

from __future__ import annotations

import copy
import ipaddress

from hydra.plugins.antidpi.model import (
    active_bans,
    expire_bans,
    record_ban_failure,
    record_manual_ban,
    record_unban,
)
from hydra.plugins.antidpi.firewall_rules import SET_V4, SET_V6
from hydra.plugins.antidpi.projection import (
    address_details as project_address_details,
)
from hydra.plugins.antidpi.projection import management_projection
from hydra.plugins.antidpi.state_store import AntiDPIStateCorruptError
from hydra.plugins.context import PluginStateAccess


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from caller input, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _is_permanent(metadata: object) -> bool:
    """Return True only for the JSON boolean ``true`` of a manual ban."""
    if not isinstance(metadata, dict):
        return False
    return isinstance(metadata.get("permanent"), bool) and metadata["permanent"]


class AntiDPIManagementMixin:
    """Keep CRUD-style management out of the plugin lifecycle facade."""

    def _load_state(self) -> dict:
        """Compatibility wrapper; new consumers use ``management_snapshot``."""
        return self._state_store().load()

    def _save_state(self, data: dict) -> None:
        self._state_store().save(data)

    def management_snapshot(self) -> dict:
        """Return bounded detector evidence without mutating runtime state."""
        try:
            with self._state_lock():
                data = self._state_store().load()
        except AntiDPIStateCorruptError as exc:
            return {
                "degraded": True,
                "state_error": str(exc),
                "ban_rows": [],
                "history": [],
            }
        return management_projection(data, now=self._clock())

    def address_details(self, address: str) -> dict:
        """Return the exact, untruncated evidence for one address.

        Bounded list projections must not decide whether an address has
        evidence: the card of the 26th watched address is as complete as
        the first.
        """
        try:
            parsed = ipaddress.ip_address(
                str(address).strip().strip("[]"),
            )
        except ValueError:
            return {"valid": False}
        try:
            with self._state_lock():
                data = self._state_store().load()
        except AntiDPIStateCorruptError as exc:
            return {"valid": True, "degraded": True, "state_error": str(exc)}
        return project_address_details(
            data,
            parsed.compressed,
            now=self._clock(),
        )

    def recent_logs(self, *, limit: int = 50) -> list[str]:
        result = self._command(
            [
                "journalctl",
                "-u",
                "hydra-antidpi",
                "-n",
                str(max(1, min(_as_int(limit, 50), 200))),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            text=True,
        )
        output = str(
            getattr(result, "stdout", "") or getattr(result, "stderr", "") or "",
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
        failed = [address for address in covered if not self.unban(address)]
        if failed:
            # The whitelist entry is saved, but the operator must see that
            # trusted addresses may still be blocked.
            self._fail(
                "Whitelist сохранён, но блокировки не сняты: " + ", ".join(failed[:8]),
            )
            return False
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

    def release_whitelisted_bans(self) -> int:
        """Drop active bans that the configured whitelist now covers."""
        with self._state_lock():
            data = self._state_store().load()
            covered = []
            for address in active_bans(data, now=self._clock()):
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if self._is_whitelisted(parsed, data):
                    covered.append(address)
        released = 0
        for address in covered:
            if self.unban(address):
                released += 1
        remaining = self.whitelisted_bans()
        if remaining:
            self._fail(
                "Whitelist-covered bans remain enforced: " + ", ".join(remaining[:8]),
            )
        return released

    def whitelisted_bans(self) -> list[str]:
        """Return active bans that must be released before restoration."""
        with self._state_lock():
            data = self._state_store().load()
            covered = []
            for address in active_bans(data, now=self._clock()):
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if self._is_whitelisted(parsed, data):
                    covered.append(address)
            return sorted(covered)

    def record_reconciliation(self, failed: list[str]) -> bool:
        """Persist the last collector reconciliation outcome for operators."""
        try:
            with self._state_lock():
                data = self._state_store().load()
                data["reconciliation"] = {
                    "ok": not failed,
                    "at": self._clock(),
                    "failed": [str(item)[:80] for item in failed[:8]],
                }
                self._state_store().save(data)
            return True
        except (OSError, RuntimeError):
            return False

    def record_collector_heartbeat(self) -> bool:
        """Persist collector liveness so health can detect a stuck worker."""
        try:
            with self._state_lock():
                data = self._state_store().load()
                data["collector_heartbeat_at"] = self._clock()
                self._state_store().save(data)
            return True
        except (OSError, RuntimeError):
            return False

    def journal_cursor(self) -> str:
        """Return the last journal record committed with detector state."""
        try:
            with self._state_lock():
                return str(
                    self._state_store().load().get("journal_cursor", ""),
                )[:4096]
        except (OSError, RuntimeError):
            return ""

    def unban(self, raw: str) -> bool:
        """Remove an address from ipset and persistent evidence atomically.

        The firewall delete and the state update share one lock: a manual
        ban from another process can no longer land between them and be
        silently forgotten by the state write.
        """
        try:
            address = ipaddress.ip_address(str(raw).strip("[]"))
        except ValueError:
            return False
        name = SET_V6 if address.version == 6 else SET_V4
        with self._state_lock():
            result = self._command(
                ["ipset", "del", name, address.compressed],
                text=True,
            )
            detail = str(
                getattr(result, "stderr", "") or getattr(result, "stdout", "") or "",
            ).lower()
            if getattr(result, "returncode", 1) != 0 and "not in set" not in detail:
                return False
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
            if isinstance(current, dict) and _is_permanent(current):
                return {
                    "ok": True,
                    "already_active": True,
                    "remaining": 0,
                    **current,
                }
            previous = copy.deepcopy(data)
            metadata = record_manual_ban(
                data,
                compressed,
                source=source,
                timestamp=timestamp,
                current=current if isinstance(current, dict) else None,
            )
            # Durable intent first: a crash after this point is healed by
            # startup reconciliation instead of leaving an untracked rule.
            self._state_store().save(data)
            if not self._add_firewall_ban(address, duration=0):
                data.clear()
                data.update(previous)
                record_ban_failure(data, compressed, now=timestamp)
                self._state_store().save(data)
                return {"ok": False, "error": "firewall_error"}
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
