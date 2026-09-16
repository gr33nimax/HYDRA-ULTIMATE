"""AmneziaWG generations: which modes exist and which fields carry them.

The interface-file reader went with the installer-era path: the core serves the tunnel from desired
state, so nothing here parses a file any more.
"""

from __future__ import annotations

AWG_PROTOCOL_MODES = ("2.0", "3.0", "3.1")
# The fields the installer-era configuration carried. Kept so an old value stays recognisable when
# HYDRA reads back what it generated, and so nothing silently reinterprets one.
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


class AwgDirectiveError(ValueError):
    """An AmneziaWG mode or generation value cannot be represented."""


def canonical_mode(value: object) -> str:
    """Normalize a persisted mode to one of 2.0, 3.0 or 3.1."""
    text = str(value).strip()
    if text not in AWG_PROTOCOL_MODES:
        raise AwgDirectiveError(f"unsupported AmneziaWG protocol mode: {text!r}")
    return text
