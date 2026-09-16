"""AntiDPI lifecycle facade over the injected privileged runtime."""

from __future__ import annotations

import ipaddress

from hydra.plugins.antidpi.model import active_bans
from hydra.plugins.antidpi.firewall_rules import SET_V4, SET_V6
from hydra.plugins.antidpi.runtime import AntiDPIRuntime
from hydra.plugins.antidpi.state_store import AntiDPIStateCorruptError
from hydra.plugins.base import HealthResult, PluginStatus
from hydra.plugins.context import PluginStateAccess

# The collector writes its heartbeat once a minute; ten missed beats mean
# the worker is stuck even though systemd still reports the unit active.
COLLECTOR_HEARTBEAT_STALE = 600.0


def _is_true(value: object) -> bool:
    """Return True only for the JSON boolean ``true``."""
    return isinstance(value, bool) and value


def _is_false(value: object) -> bool:
    """Return True only for the JSON boolean ``false``."""
    return isinstance(value, bool) and not value


class AntiDPILifecycleMixin:
    """Install, health, enable, and cleanup orchestration."""

    def install(self) -> bool:
        """Provision executable assets without activating the detector."""
        self.last_error = ""
        missing = [name for name in self.meta.required_commands if self._host_command().which(name) is None]
        if missing:
            self._install_host_dependencies(missing)
            missing = [name for name in self.meta.required_commands if self._host_command().which(name) is None]
        if missing:
            return self._fail("Не найдены команды: " + ", ".join(missing))
        try:
            self._write_service()
        except OSError as exc:
            return self._fail(f"Не удалось записать systemd unit: {exc}")
        result = self._command(["systemctl", "daemon-reload"], text=True)
        if getattr(result, "returncode", 1) != 0:
            return self._fail(
                self._result_error(result, "systemctl daemon-reload"),
            )
        paths = self._runtime_paths()
        return paths.script.exists() and paths.service.exists()

    def _install_host_dependencies(self, missing: list[str]) -> None:
        self._runtime().install_dependencies(missing)

    def uninstall(self) -> bool:
        self._command(["systemctl", "disable", "--now", "hydra-antidpi"])
        ok = self._remove_obsolete_telemetry()
        ok = self._remove_rules() and ok
        for name in (SET_V4, SET_V6):
            self._command(["ipset", "flush", name])
            self._command(["ipset", "destroy", name])
        paths = self._runtime_paths()
        for path in (paths.script, paths.service, paths.state):
            path.unlink(missing_ok=True)
        return ok

    def _restore_bans(self) -> bool:
        return self._runtime().restore_bans(self._state_store())

    def reconcile_enforcement(self, state: PluginStateAccess) -> bool:
        """Restore every AntiDPI firewall object and expose failed steps."""
        if _is_true(self.management_snapshot().get("degraded")):
            return self._fail(
                "AntiDPI state is degraded; automatic enforcement is paused",
            )
        failed: list[str] = []
        reasons: list[str] = []
        del state
        steps = (
            ("ipset sets", self._ensure_sets),
            ("INPUT rules", self._ensure_rules),
            ("obsolete telemetry cleanup", self._remove_obsolete_telemetry),
        )
        for label, action in steps:
            # Each step writes its own cause into ``last_error``; reporting the
            # bare label would hide why iptables refused, which is exactly how
            # a missing CAP_NET_RAW stayed invisible behind "INPUT rules".
            self.last_error = ""
            try:
                done = action()
            except Exception as exc:
                reasons.append(f"{label}: {type(exc).__name__}: {exc}")
                failed.append(label)
                continue
            if not done:
                reasons.append(
                    f"{label}: {self.last_error or 'шаг вернул False'}",
                )
                failed.append(label)
        try:
            self.release_whitelisted_bans()
            covered = self.whitelisted_bans()
        except Exception as exc:
            covered = ["state read failed"]
            reasons.append(f"whitelist-covered bans: {type(exc).__name__}: {exc}")
        if covered:
            failed.append("whitelist-covered bans")
        else:
            self.last_error = ""
            try:
                restored = self._restore_bans()
            except Exception as exc:
                reasons.append(f"stored bans: {type(exc).__name__}: {exc}")
                failed.append("stored bans")
            else:
                if not restored:
                    reasons.append(
                        f"stored bans: {self.last_error or 'шаг вернул False'}",
                    )
                    failed.append("stored bans")
        if not self.record_reconciliation(failed):
            return self._fail("Could not persist reconciliation outcome")
        if failed:
            return self._fail(
                "Reconciliation failed: "
                + ", ".join(failed)
                + " — "
                + "; ".join(reasons),
            )
        self.last_error = ""
        return True

    def sync_runtime(self, state: PluginStateAccess) -> bool:
        """Restart an enabled detector and reconcile its firewall runtime."""
        protocol = state.protocols.get("antidpi")
        if protocol and protocol.enabled:
            result = self._command(
                ["systemctl", "restart", "hydra-antidpi"],
                text=True,
            )
            if getattr(result, "returncode", 1) != 0:
                return self._fail(
                    self._result_error(result, "restart hydra-antidpi"),
                )
        return self.reconcile_enforcement(state)

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        del state
        active = self._command(
            ["systemctl", "is-active", "hydra-antidpi"],
            text=True,
        )
        running = getattr(active, "returncode", 1) == 0 and str(getattr(active, "stdout", "")).strip() == "active"
        degraded = False
        try:
            data = self._state_store().load()
        except AntiDPIStateCorruptError as exc:
            data = {}
            degraded = True
            self._fail(str(exc))
        paths = self._runtime_paths()
        return PluginStatus(
            installed=paths.script.exists() or paths.service.exists(),
            enabled=running,
            running=running,
            info={
                "banned_ips": len(active_bans(data)),
                "events": data.get("events", 0),
                "last_error": self.last_error,
                "state_degraded": degraded,
                "reconciliation": data.get("reconciliation", {}),
            },
        )

    def healthcheck(self) -> HealthResult:
        return self._healthcheck(mieru_enabled=False)

    def healthcheck_for_state(
        self,
        state: PluginStateAccess,
    ) -> HealthResult:
        del state
        return self._healthcheck()

    def _healthcheck(self) -> HealthResult:
        checks = self._runtime().health_checks(
            running=self.status().running,
        )
        checks["collector_heartbeat"] = self._collector_heartbeat_ok()
        checks.update(self._persisted_health_checks())
        healthy = all(checks.values())
        return HealthResult(
            healthy,
            "" if healthy else "anti-DPI runtime is incomplete",
            "ok" if healthy else "error",
            checks,
        )

    def _collector_heartbeat_ok(self) -> bool:
        """Fail health when the collector is running but has gone silent.

        A missing heartbeat (pre-upgrade state) is not a failure: only a
        recorded heartbeat that has gone stale proves a stuck collector.
        """
        try:
            data = self._state_store().load()
        except AntiDPIStateCorruptError:
            return False
        except Exception:
            return True
        try:
            heartbeat = float(data.get("collector_heartbeat_at", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            return True
        if heartbeat <= 0:
            return True
        return self._clock() - heartbeat <= COLLECTOR_HEARTBEAT_STALE

    def _persisted_health_checks(self) -> dict[str, bool]:
        try:
            data = self._state_store().load()
        except AntiDPIStateCorruptError:
            return {"state": False, "reconciliation": False}
        reconciliation = data.get("reconciliation", {})
        return {
            "state": True,
            "reconciliation": not isinstance(reconciliation, dict) or not _is_false(reconciliation.get("ok")),
        }

    def on_enable(self, state: PluginStateAccess) -> None:
        del state
        prepared = (
            self._ensure_sets()
            and self._ensure_rules()
            and self._remove_obsolete_telemetry()
            and self.release_whitelisted_bans() >= 0
            and not self.whitelisted_bans()
            and self._restore_bans()
        )
        if not prepared:
            raise RuntimeError(
                self.last_error or "Anti-DPI firewall runtime could not be prepared",
            )
        try:
            self._write_service()
        except OSError as exc:
            raise RuntimeError(
                f"Anti-DPI unit could not be written: {exc}",
            ) from exc
        reload_result = self._command(
            ["systemctl", "daemon-reload"],
            text=True,
        )
        if getattr(reload_result, "returncode", 1) != 0:
            raise RuntimeError(
                self._result_error(
                    reload_result,
                    "systemctl daemon-reload",
                ),
            )
        start_result = self._command(
            ["systemctl", "enable", "--now", "hydra-antidpi"],
            text=True,
        )
        if getattr(start_result, "returncode", 1) != 0 or not self.status().running:
            raise RuntimeError(
                self._result_error(start_result, "запуск hydra-antidpi"),
            )

    def on_disable(self, state: PluginStateAccess) -> None:
        del state
        result = self._command(
            ["systemctl", "disable", "--now", "hydra-antidpi"],
        )
        if getattr(result, "returncode", 1) != 0:
            raise RuntimeError("Anti-DPI service could not be stopped")
        cleanup_results = (
            self._remove_rules(),
            self._remove_obsolete_telemetry(),
        )
        if not all(cleanup_results):
            raise RuntimeError("Anti-DPI firewall rules could not be removed")

    def _ensure_sets(self) -> bool:
        return self._runtime().ensure_sets()

    def _ensure_rules(self) -> bool:
        return self._runtime().ensure_rules()

    def _remove_rules(self) -> bool:
        return self._runtime().remove_rules()

    def _remove_obsolete_telemetry(self) -> bool:
        """Delete scan/UDP/Mieru logging rules left by earlier versions."""
        return self._runtime().remove_obsolete_telemetry()

    def _add_firewall_ban(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        *,
        duration: int,
    ) -> bool:
        set_name = SET_V6 if address.version == 6 else SET_V4
        result = self._command(
            [
                "ipset",
                "add",
                set_name,
                address.compressed,
                "timeout",
                str(duration),
                "-exist",
            ],
            text=True,
        )
        return getattr(result, "returncode", 1) == 0

    def _write_service(self) -> None:
        self._runtime().write_service()

    @staticmethod
    def _result_error(result: object, action: str) -> str:
        return AntiDPIRuntime.result_error(result, action)
