"""Privileged AntiDPI firewall adapter over an injected command runner."""
from __future__ import annotations

from collections.abc import Callable

from hydra.plugins.antidpi.firewall_rules import (
    MIERU_PROBE_RULE_COMMENT,
    RULE_COMMENT,
    SET_V4,
    SET_V6,
    UDP_PROBE_CHAIN,
    UDP_PROBE_RULE_COMMENT,
    mieru_probe_rule,
    scan_rule,
)

CommandRunner = Callable[..., object]
FailureReporter = Callable[[str], bool]


class FirewallAdapter:
    """Install, remove, and inspect only AntiDPI-owned firewall objects."""

    def __init__(
        self,
        *,
        run: CommandRunner,
        fail: FailureReporter,
    ) -> None:
        self.run = run
        self.fail = fail

    @staticmethod
    def result_error(result: object, action: str) -> str:
        detail = (
            getattr(result, "stderr", "")
            or getattr(result, "stdout", "")
            or "неизвестная ошибка"
        )
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        return f"{action}: {' '.join(str(detail).split())[:650]}"

    def ensure_sets(self) -> bool:
        ok = True
        for name, family in ((SET_V4, "inet"), (SET_V6, "inet6")):
            result = self.run(
                [
                    "ipset",
                    "create",
                    name,
                    "hash:ip",
                    "family",
                    family,
                    "timeout",
                    "86400",
                    "-exist",
                ],
                text=True,
            )
            if getattr(result, "returncode", 1) != 0:
                self.fail(self.result_error(result, f"создание ipset {name}"))
                ok = False
        return ok

    def ensure_rules(self) -> bool:
        ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            rule = [
                binary,
                "-C",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                name,
                "src",
                "-m",
                "comment",
                "--comment",
                RULE_COMMENT,
                "-j",
                "DROP",
            ]
            if getattr(self.run(rule), "returncode", 1) == 0:
                continue
            result = self.run(
                [binary, "-I", "INPUT", "1", *rule[3:]],
                text=True,
            )
            if getattr(result, "returncode", 1) != 0:
                self.fail(self.result_error(result, f"правило {binary} для {name}"))
                ok = False
        return ok

    def remove_rules(self) -> bool:
        ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            check = [
                binary,
                "-C",
                "INPUT",
                "-m",
                "set",
                "--match-set",
                name,
                "src",
                "-m",
                "comment",
                "--comment",
                RULE_COMMENT,
                "-j",
                "DROP",
            ]
            for _ in range(32):
                if getattr(self.run(check), "returncode", 1) != 0:
                    break
                if getattr(
                    self.run([binary, "-D", *check[2:]]),
                    "returncode",
                    1,
                ) != 0:
                    ok = False
                    break
        return ok

    def ensure_scan_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for protocol in ("tcp", "udp"):
                spec = scan_rule(binary, protocol)
                if getattr(
                    self.run([binary, "-C", "INPUT", *spec]),
                    "returncode",
                    1,
                ) == 0:
                    continue
                result = self.run(
                    [binary, "-I", "INPUT", "2", *spec],
                    text=True,
                )
                if getattr(result, "returncode", 1) != 0:
                    self.fail(
                        self.result_error(
                            result,
                            f"scan telemetry {binary}/{protocol}",
                        ),
                    )
                    ok = False
        return ok

    def remove_scan_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for protocol in ("tcp", "udp"):
                spec = scan_rule(binary, protocol)
                check = [binary, "-C", "INPUT", *spec]
                for _ in range(32):
                    if getattr(self.run(check), "returncode", 1) != 0:
                        break
                    if getattr(
                        self.run([binary, "-D", "INPUT", *spec]),
                        "returncode",
                        1,
                    ) != 0:
                        ok = False
                        break
        return ok

    def remove_udp_probe_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            jump = [
                "-p",
                "udp",
                "-m",
                "comment",
                "--comment",
                UDP_PROBE_RULE_COMMENT,
                "-j",
                UDP_PROBE_CHAIN,
            ]
            for _ in range(8):
                if getattr(
                    self.run([binary, "-C", "INPUT", *jump]),
                    "returncode",
                    1,
                ) != 0:
                    break
                ok = (
                    getattr(
                        self.run([binary, "-D", "INPUT", *jump]),
                        "returncode",
                        1,
                    )
                    == 0
                    and ok
                )
            self.run([binary, "-F", UDP_PROBE_CHAIN])
            result = self.run([binary, "-X", UDP_PROBE_CHAIN])
            if getattr(result, "returncode", 1) != 0:
                detail = str(
                    getattr(result, "stderr", "")
                    or getattr(result, "stdout", "")
                    or ""
                ).lower()
                if "no chain" not in detail and "does not exist" not in detail:
                    ok = False
        return ok

    def sync_mieru_probe_rules(self, enabled: bool) -> bool:
        ok = self.remove_mieru_probe_rules()
        if not enabled:
            return ok
        for binary in ("iptables", "ip6tables"):
            for flag in ("FIN", "RST"):
                spec = mieru_probe_rule(binary, flag)
                result = self.run(
                    [binary, "-I", "INPUT", "2", *spec],
                    text=True,
                )
                if getattr(result, "returncode", 1) != 0:
                    self.fail(
                        self.result_error(
                            result,
                            f"Mieru telemetry {binary}/{flag}",
                        ),
                    )
                    ok = False
        return ok

    def remove_mieru_probe_rules(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            for flag in ("FIN", "RST"):
                spec = mieru_probe_rule(binary, flag)
                for _ in range(8):
                    if getattr(
                        self.run([binary, "-C", "INPUT", *spec]),
                        "returncode",
                        1,
                    ) != 0:
                        break
                    if getattr(
                        self.run([binary, "-D", "INPUT", *spec]),
                        "returncode",
                        1,
                    ) != 0:
                        ok = False
                        break
        return ok

    def health_checks(self, *, running: bool, mieru_enabled: bool) -> dict:
        sets_ok = all(
            getattr(self.run(["ipset", "list", name]), "returncode", 1) == 0
            for name in (SET_V4, SET_V6)
        )
        rules_ok = telemetry_ok = udp_probe_ok = mieru_probe_ok = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            rules_ok = self._enforcement_rule_ok(binary, name) and rules_ok
            telemetry_ok = self._scan_rules_ok(binary) and telemetry_ok
            udp_probe_ok = self._udp_probe_absent(binary) and udp_probe_ok
            if mieru_enabled:
                mieru_probe_ok = (
                    self._mieru_rules_ok(binary) and mieru_probe_ok
                )
        return {
            "service": running,
            "ipsets": sets_ok,
            "firewall": rules_ok,
            "scan_telemetry": telemetry_ok,
            "udp_probe_telemetry_removed": udp_probe_ok,
            "mieru_probe_telemetry": mieru_probe_ok,
        }

    def _enforcement_rule_ok(self, binary: str, name: str) -> bool:
        command = [
            binary,
            "-C",
            "INPUT",
            "-m",
            "set",
            "--match-set",
            name,
            "src",
            "-m",
            "comment",
            "--comment",
            RULE_COMMENT,
            "-j",
            "DROP",
        ]
        return getattr(self.run(command), "returncode", 1) == 0

    def _scan_rules_ok(self, binary: str) -> bool:
        return all(
            getattr(
                self.run(
                    [binary, "-C", "INPUT", *scan_rule(binary, protocol)],
                ),
                "returncode",
                1,
            )
            == 0
            for protocol in ("tcp", "udp")
        )

    def _udp_probe_absent(self, binary: str) -> bool:
        jump = [
            "-p",
            "udp",
            "-m",
            "comment",
            "--comment",
            UDP_PROBE_RULE_COMMENT,
            "-j",
            UDP_PROBE_CHAIN,
        ]
        return (
            getattr(
                self.run([binary, "-C", "INPUT", *jump]),
                "returncode",
                1,
            )
            != 0
        )

    def _mieru_rules_ok(self, binary: str) -> bool:
        return all(
            getattr(
                self.run(
                    [binary, "-C", "INPUT", *mieru_probe_rule(binary, flag)],
                ),
                "returncode",
                1,
            )
            == 0
            for flag in ("FIN", "RST")
        )

