"""Generation-aware AmneziaWG interface directive handling."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping


AWG_PROTOCOL_MODES = ("2.0", "3.0", "3.1")
# wg-quick runs each of these hooks, so a configuration may carry several of them — upstream's own
# installer writes two PostUp lines. They are not directives HYDRA interprets, and treating a
# repeat as a duplicate made an existing server's AWG config unreadable, which is where its update
# stopped. Two values for a directive HYDRA does interpret stay an error.
REPEATABLE_DIRECTIVE_KEYS = ("PreUp", "PostUp", "PreDown", "PostDown")
LEGACY_DIRECTIVE_KEYS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
)
AWG3_DIRECTIVE_KEYS = (
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
)
AWG3_OPTIONAL_DIRECTIVE_KEYS = ("MaxHandshakeAttempts",)
AWG31_DIRECTIVE_KEYS = ("RandomTrailers", "DisableCookies")
GENERATION_DIRECTIVE_KEYS = (
    *AWG3_DIRECTIVE_KEYS,
    *AWG3_OPTIONAL_DIRECTIVE_KEYS,
    *AWG31_DIRECTIVE_KEYS,
)
_ASSIGNMENT = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")


class AwgDirectiveError(ValueError):
    """An interface block cannot safely represent its requested AWG mode."""


def canonical_mode(value: object, *, from_upstream: bool = False) -> str:
    """Normalize persisted modes, optionally accepting upstream status values."""
    text = str(value).strip()
    if from_upstream:
        text = {"2": "2.0", "3": "3.0"}.get(text, text)
    if text not in AWG_PROTOCOL_MODES:
        raise AwgDirectiveError(f"unsupported AmneziaWG protocol mode: {text!r}")
    return text


@dataclass(frozen=True)
class AwgInterfaceDirectives:
    """Known interface directives without owning their secret values."""

    values: Mapping[str, str]
    mode: str | None = None

    @classmethod
    def parse(cls, text: str) -> "AwgInterfaceDirectives":
        """Parse one config's interface section and reject duplicate keys."""
        in_interface = False
        found_interface = False
        values: dict[str, str] = {}
        for line in text.splitlines():
            section = line.strip()
            if section == "[Interface]":
                if found_interface:
                    raise AwgDirectiveError("duplicate [Interface] section")
                found_interface = in_interface = True
                continue
            if in_interface and section.startswith("[") and section.endswith("]"):
                break
            if not in_interface:
                continue
            match = _ASSIGNMENT.match(line)
            if not match:
                continue
            key, value = match.groups()
            if key in values and key not in REPEATABLE_DIRECTIVE_KEYS:
                raise AwgDirectiveError(f"duplicate AmneziaWG directive: {key}")
            values.setdefault(key, value)
        if not found_interface:
            raise AwgDirectiveError("missing [Interface] section")
        return cls(values=values)

    def for_mode(self, mode: object) -> "AwgInterfaceDirectives":
        """Validate this parsed directive set for one canonical generation."""
        canonical = canonical_mode(mode)
        present = set(self.values).intersection(GENERATION_DIRECTIVE_KEYS)
        if canonical == "2.0":
            if present:
                raise AwgDirectiveError(
                    "AWG 3.x directives are not allowed in mode 2.0",
                )
            return AwgInterfaceDirectives(self.values, canonical)

        required: set[str] = set(AWG3_DIRECTIVE_KEYS)
        if canonical == "3.1":
            required.add("RandomTrailers")
        missing = sorted(key for key in required if not self.values.get(key))
        if missing:
            raise AwgDirectiveError(
                f"missing required AWG {canonical} directive: {', '.join(missing)}",
            )

        forbidden = set(AWG31_DIRECTIVE_KEYS) if canonical == "3.0" else set()
        unsupported = sorted(present.intersection(forbidden))
        if unsupported:
            raise AwgDirectiveError(
                f"AWG 3.1 directive is not allowed in mode 3.0: {', '.join(unsupported)}",
            )
        disable_cookies = self.values.get("DisableCookies", "").strip().lower()
        if disable_cookies not in ("", "0", "false", "off", "no"):
            raise AwgDirectiveError("DisableCookies must remain disabled")
        return AwgInterfaceDirectives(self.values, canonical)

    def replace_generation_directives(self, interface_text: str) -> str:
        """Copy validated generation fields into another config without collateral loss."""
        if self.mode is None:
            raise AwgDirectiveError("generation directives must be validated before copy")
        lines = interface_text.splitlines()
        start = next(
            (index for index, line in enumerate(lines) if line.strip() == "[Interface]"),
            None,
        )
        if start is None:
            raise AwgDirectiveError("target config is missing [Interface] section")
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index].strip().startswith("[") and lines[index].strip().endswith("]")
            ),
            len(lines),
        )
        retained = [lines[start]]
        for line in lines[start + 1 : end]:
            match = _ASSIGNMENT.match(line)
            if match and match.group(1) in GENERATION_DIRECTIVE_KEYS:
                continue
            retained.append(line)
        while len(retained) > 1 and not retained[-1].strip():
            retained.pop()
        for key in GENERATION_DIRECTIVE_KEYS:
            value = self.values.get(key)
            if value not in (None, ""):
                retained.append(f"{key} = {value}")
        return "\n".join([*lines[:start], *retained, "", *lines[end:]]).rstrip() + "\n"

    def summary(self) -> dict[str, str]:
        """Return status-safe information without directive values or keys."""
        if self.mode is None:
            raise AwgDirectiveError("generation directives must be validated before summary")
        return {
            "mode": self.mode,
            "generation_directives": "present" if self.mode != "2.0" else "absent",
        }
