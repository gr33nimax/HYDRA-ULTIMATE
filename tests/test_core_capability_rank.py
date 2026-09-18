"""Capability gates must read both HydraCore version naming schemes.

The gates for the upstream Snell generations and the AWG 3.1 fields were written
against the legacy tag `v1.14.0-extended-2.7.1-hydracore.12`, where the trailing
cycle says which Hydra side the core is. The readable contract
`hydracore-sbe-1.14.0` names the upstream baseline instead, so a plain numeric
comparison of the two strings reads a new core as older than the release that
introduced those capabilities.
"""

from hydra.core.singbox_upgrade import (
    MIN_UPSTREAM_CAPABILITY_CORE,
    core_capability_rank,
    core_supports_upstream_capability,
)


def test_readable_contract_ranks_at_its_baseline_line():
    rank = core_capability_rank("hydracore-sbe-1.14.0")

    assert rank is not None
    assert rank[:3] == (1, 14, 0)
    assert rank >= MIN_UPSTREAM_CAPABILITY_CORE
    assert core_supports_upstream_capability("hydracore-sbe-1.14.0") is True
    assert core_supports_upstream_capability("hydracore-sbe-1.14.0-debug-7") is True
    assert core_supports_upstream_capability("hydracore-sbe-1.14.0-rc-1") is True


def test_readable_contract_below_the_baseline_is_not_supported():
    assert core_supports_upstream_capability("hydracore-sbe-1.13.16") is False
    assert core_supports_upstream_capability("hydracore-sbe-1.13.16-debug-4") is False


def test_legacy_contract_still_ranks_by_its_cycle():
    assert core_capability_rank("v1.14.0-extended-2.7.1-hydracore.12") == (1, 14, 0, 12)
    assert core_supports_upstream_capability("v1.14.0-extended-2.7.1-hydracore.12-debug.2") is True
    assert core_supports_upstream_capability("v1.14.0-extended-2.7.1-hydracore.11") is False
    assert core_supports_upstream_capability("v1.13.16-extended-hydracore.11-debug.61") is False


def test_unknown_versions_are_never_supported():
    for value in (None, "", "sing-box version", "v1.14.0"):
        assert core_capability_rank(value) is None
        assert core_supports_upstream_capability(value) is False
