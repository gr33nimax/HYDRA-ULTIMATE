"""warpscout binary lifecycle: verified install, clean removal, wiring."""

from __future__ import annotations

import tarfile
from pathlib import Path

from hydra.plugins.warp import masque_scan


def _write_elf(path: Path) -> None:
    path.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 24)


def test_install_warpscout_atomically_places_a_verified_binary(tmp_path, monkeypatch):
    binary = tmp_path / "warpscout"
    monkeypatch.setattr(masque_scan, "WARPSCOUT_BIN", binary)

    source = tmp_path / "src-warpscout"
    _write_elf(source)

    def fake_download(repo, name_filter, dest, *, require_unique=False, require_digest=False, on_error=None):
        assert name_filter("warpscout_0.16.0_linux_amd64.tar.gz")
        assert not name_filter("warpscout_0.16.0_windows_amd64.zip")
        with tarfile.open(dest, "w:gz") as archive:
            archive.add(source, arcname="warpscout")
        return True

    monkeypatch.setattr(masque_scan, "download_github_asset_filtered", fake_download)

    assert masque_scan.install_warpscout() is True
    assert binary.exists()
    assert binary.read_bytes().startswith(b"\x7fELF")
    assert not binary.with_suffix(".pending").exists()


def test_install_warpscout_reports_download_failure_and_installs_nothing(tmp_path, monkeypatch):
    binary = tmp_path / "warpscout"
    monkeypatch.setattr(masque_scan, "WARPSCOUT_BIN", binary)

    def failing_download(repo, name_filter, dest, *, require_unique=False, require_digest=False, on_error=None):
        if on_error is not None:
            on_error("в релизах нет подходящего архива")
        return False

    monkeypatch.setattr(masque_scan, "download_github_asset_filtered", failing_download)

    reasons: list[str] = []
    assert masque_scan.install_warpscout(on_failure=reasons.append) is False
    assert reasons and "нет подходящего архива" in reasons[-1]
    assert not binary.exists()


def test_install_warpscout_rejects_a_non_elf_payload(tmp_path, monkeypatch):
    binary = tmp_path / "warpscout"
    monkeypatch.setattr(masque_scan, "WARPSCOUT_BIN", binary)

    junk = tmp_path / "src-warpscout"
    junk.write_bytes(b"not an elf")

    def fake_download(repo, name_filter, dest, *, require_unique=False, require_digest=False, on_error=None):
        with tarfile.open(dest, "w:gz") as archive:
            archive.add(junk, arcname="warpscout")
        return True

    monkeypatch.setattr(masque_scan, "download_github_asset_filtered", fake_download)

    reasons: list[str] = []
    assert masque_scan.install_warpscout(on_failure=reasons.append) is False
    assert not binary.exists()


def test_remove_warpscout_deletes_the_binary_and_account_dir(tmp_path, monkeypatch):
    binary = tmp_path / "warpscout"
    binary.write_bytes(b"x")
    account = tmp_path / "warpscout-data" / "account.json"
    account.parent.mkdir()
    account.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(masque_scan, "WARPSCOUT_BIN", binary)
    monkeypatch.setattr(masque_scan, "ACCOUNT", account)

    assert masque_scan.remove_warpscout() is True
    assert not binary.exists()
    assert not account.parent.exists()


def test_remove_warpscout_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(masque_scan, "WARPSCOUT_BIN", tmp_path / "absent")
    monkeypatch.setattr(masque_scan, "ACCOUNT", tmp_path / "absent-dir" / "account.json")
    assert masque_scan.remove_warpscout() is True


def test_warp_plugin_registers_warpscout_actions():
    from hydra.plugins.warp.plugin import WarpPlugin

    assert "install_warpscout_binary" in WarpPlugin.meta.actions
    assert "remove_warpscout_binary" in WarpPlugin.meta.actions


def test_full_uninstall_sweeps_the_warpscout_binary():
    from hydra.core import uninstall

    assert Path("/usr/local/bin/warpscout") in uninstall.PROGRAM_PATHS
