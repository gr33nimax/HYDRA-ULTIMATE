from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hydra.core import nft


def test_snapshot_captures_only_hydra_table_and_policy_route():
    table = MagicMock(returncode=0, stdout="table inet hydra-tproxy { }\n")
    rule = MagicMock(returncode=0, stdout="100: from all fwmark 0x1 lookup 100\n")
    with (
        patch.object(nft.HOST, "which", return_value="/usr/sbin/tool"),
        patch.object(nft.HOST, "run", side_effect=[table, rule]),
    ):
        snapshot = nft.snapshot_tproxy()
    assert snapshot.ruleset == "table inet hydra-tproxy { }\n"
    assert snapshot.policy_routing is True


def test_restore_replaces_only_hydra_table():
    snapshot = nft.TproxySnapshot("table inet hydra-tproxy { }\n", True)
    with (
        patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"),
        patch.object(nft.HOST, "run") as run,
        patch.object(nft, "_run_checked") as checked,
        patch.object(nft, "_ensure_policy_routing") as routing,
    ):
        nft.restore_tproxy(snapshot)
    run.assert_called_once_with(
        ["nft", "delete", "table", "inet", nft.NFT_TABLE],
    )
    checked.assert_called_once()
    routing.assert_called_once()


def test_restore_empty_snapshot_removes_hydra_policy_only():
    snapshot = nft.TproxySnapshot(None, False)
    with (
        patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"),
        patch.object(nft.HOST, "run"),
        patch.object(nft, "_cleanup_policy_routing") as cleanup,
    ):
        nft.restore_tproxy(snapshot)
    cleanup.assert_called_once()


def test_apply_without_fragments_never_requires_the_tproxy_runtime():
    # A fresh install creates its first user before any transport exists. Asking the host for
    # TPROXY at that point is what broke installation on machines without nft or the kernel
    # modules, so nothing may run at all here.
    with (
        patch.object(nft.HOST, "which", return_value=None),
        patch.object(nft.HOST, "run") as run,
        patch.object(nft, "_run_checked") as checked,
        patch.object(nft, "_cleanup_policy_routing") as cleanup,
    ):
        nft.apply_tproxy({})
    run.assert_not_called()
    checked.assert_not_called()
    cleanup.assert_not_called()


def test_apply_without_fragments_still_clears_an_existing_table():
    with (
        patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"),
        patch.object(nft.HOST, "run") as run,
        patch.object(nft, "_run_checked") as checked,
        patch.object(nft, "_cleanup_policy_routing") as cleanup,
    ):
        nft.apply_tproxy({})
    run.assert_called_once_with(["nft", "delete", "table", "inet", nft.NFT_TABLE])
    cleanup.assert_called_once()
    checked.assert_not_called()


def test_apply_with_ports_checks_the_host_before_running_anything():
    fragment = SimpleNamespace(nft_tproxy_ports=[443], nft_tproxy_ifaces=[])
    with (
        patch.object(nft.HOST, "which", return_value=None),
        patch.object(nft.HOST, "run") as run,
        patch.object(nft, "_run_checked") as checked,
    ):
        with pytest.raises(RuntimeError, match="nftables"):
            nft.apply_tproxy({"p": fragment})
    run.assert_not_called()
    checked.assert_not_called()


def test_a_missing_kernel_module_is_reported_as_a_host_limitation():
    fragment = SimpleNamespace(nft_tproxy_ports=[443], nft_tproxy_ifaces=[])
    with (
        patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"),
        patch.object(nft, "_run_checked", side_effect=RuntimeError("modprobe nft_tproxy failed")),
    ):
        with pytest.raises(RuntimeError, match="TPROXY"):
            nft.apply_tproxy({"p": fragment})
