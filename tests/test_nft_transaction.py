from unittest.mock import MagicMock, patch

from hydra.core import nft


def test_snapshot_captures_only_hydra_table_and_policy_route():
    table = MagicMock(returncode=0, stdout="table inet hydra-tproxy { }\n")
    rule = MagicMock(returncode=0, stdout="100: from all fwmark 0x1 lookup 100\n")
    with patch.object(nft.HOST, "which", return_value="/usr/sbin/tool"), \
         patch.object(nft.HOST, "run", side_effect=[table, rule]):
        snapshot = nft.snapshot_tproxy()
    assert snapshot.ruleset == "table inet hydra-tproxy { }\n"
    assert snapshot.policy_routing is True


def test_restore_replaces_only_hydra_table():
    snapshot = nft.TproxySnapshot("table inet hydra-tproxy { }\n", True)
    with patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"), \
         patch.object(nft.HOST, "run") as run, \
         patch.object(nft, "_run_checked") as checked, \
         patch.object(nft, "_ensure_policy_routing") as routing:
        nft.restore_tproxy(snapshot)
    run.assert_called_once_with(
        ["nft", "delete", "table", "inet", nft.NFT_TABLE],
    )
    checked.assert_called_once()
    routing.assert_called_once()


def test_restore_empty_snapshot_removes_hydra_policy_only():
    snapshot = nft.TproxySnapshot(None, False)
    with patch.object(nft.HOST, "which", return_value="/usr/sbin/nft"), \
         patch.object(nft.HOST, "run"), \
         patch.object(nft, "_cleanup_policy_routing") as cleanup:
        nft.restore_tproxy(snapshot)
    cleanup.assert_called_once()
