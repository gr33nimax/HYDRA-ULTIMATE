"""Privileged AntiDPI firewall adapter over an injected command runner."""

from __future__ import annotations

import shlex
from collections.abc import Callable

from hydra.plugins.antidpi.firewall_rules import (
    OBSOLETE_LOG_PREFIXES,
    OBSOLETE_RULE_COMMENTS,
    OBSOLETE_UDP_PROBE_CHAIN,
    RULE_COMMENT,
    SET_V4,
    SET_V6,
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
        self._run = run
        self.fail = fail

    def run(self, command: list[str], **options: object) -> object:
        if command and command[0] in {"iptables", "ip6tables"}:
            command = [command[0], "-w", "10", *command[1:]]
        return self._run(command, **options)

    @staticmethod
    def result_error(result: object, action: str) -> str:
        detail = getattr(result, "stderr", "") or getattr(result, "stdout", "") or "неизвестная ошибка"
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
                if (
                    getattr(
                        self.run([binary, "-D", *check[2:]]),
                        "returncode",
                        1,
                    )
                    != 0
                ):
                    ok = False
                    break
        return ok

    def remove_obsolete_telemetry(self) -> bool:
        """Delete scan/UDP/Mieru telemetry rules owned by earlier versions.

        The contraction removed every observation that consumed this
        telemetry, so an upgraded host must not keep logging rules for it.
        """
        ok = True
        for binary in ("iptables", "ip6tables"):
            for spec in self._obsolete_input_rules(binary):
                for _ in range(32):
                    if (
                        getattr(
                            self.run([binary, "-C", "INPUT", *spec]),
                            "returncode",
                            1,
                        )
                        != 0
                    ):
                        break
                    if (
                        getattr(
                            self.run([binary, "-D", "INPUT", *spec]),
                            "returncode",
                            1,
                        )
                        != 0
                    ):
                        ok = False
                        break
            self.run([binary, "-F", OBSOLETE_UDP_PROBE_CHAIN])
            result = self.run([binary, "-X", OBSOLETE_UDP_PROBE_CHAIN])
            if getattr(result, "returncode", 1) != 0:
                detail = str(
                    getattr(result, "stderr", "") or getattr(result, "stdout", "") or "",
                ).lower()
                if "no chain" not in detail and "does not exist" not in detail:
                    ok = False
        return ok

    def _obsolete_input_rules(self, binary: str) -> list[list[str]]:
        """Return INPUT rule specs whose markers belong to obsolete telemetry."""
        result = self.run([binary, "-S", "INPUT"], text=True)
        if getattr(result, "returncode", 1) != 0:
            return []
        markers = (*OBSOLETE_RULE_COMMENTS, *OBSOLETE_LOG_PREFIXES)
        specs: list[list[str]] = []
        for line in str(getattr(result, "stdout", "") or "").splitlines():
            stripped = line.strip()
            if not stripped.startswith("-A INPUT"):
                continue
            if not any(marker in stripped for marker in markers):
                continue
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                continue
            if len(tokens) < 3 or tokens[0] != "-A" or tokens[1] != "INPUT":
                continue
            specs.append(tokens[2:])
        return specs

    def health_checks(self, *, running: bool) -> dict:
        sets_ok = all(getattr(self.run(["ipset", "list", name]), "returncode", 1) == 0 for name in (SET_V4, SET_V6))
        rules_ok = True
        telemetry_removed = True
        for binary, name in (("iptables", SET_V4), ("ip6tables", SET_V6)):
            rules_ok = self._enforcement_rule_ok(binary, name) and rules_ok
            telemetry_removed = self._obsolete_telemetry_absent(binary) and telemetry_removed
        return {
            "service": running,
            "ipsets": sets_ok,
            "firewall": rules_ok,
            "obsolete_telemetry_removed": telemetry_removed,
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

    def _obsolete_telemetry_absent(self, binary: str) -> bool:
        return not self._obsolete_input_rules(binary)
