"""Hermetic resolver, installer and stage-propagation tests for mtproto.zig.

Every case is network-free, needs no binary, no systemd, no root and no Telegram
client: the release API and the asset download are injected fakes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.invoker import PluginInvoker
from hydra.plugins.mtproto_zig import installation
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.services.plugin_lifecycle import PluginLifecycleOperations
from hydra.utils import downloader

ASSET_NAMES = ("mtproto-proxy-linux-x86_64_v3.tar.gz", "mtproto-proxy-linux-x86_64.tar.gz")
PROXY_ASSET = {"name": "mtproto-proxy-linux-x86_64.tar.gz", "browser_download_url": "https://example.invalid/a"}


class _Response:
    """Minimal urlopen stand-in that also satisfies ``shutil.copyfileobj``."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self._position = 0

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk, self._position = self._body[self._position :], len(self._body)
            return chunk
        chunk = self._body[self._position : self._position + size]
        self._position += len(chunk)
        return chunk


def _github(releases: list[dict], asset_bytes: bytes = b"payload"):
    """Serve the releases API for API URLs and the asset bytes for downloads."""

    def open_url(request, timeout=None):  # noqa: ARG001 - urlopen signature
        url = getattr(request, "full_url", str(request))
        return _Response(json.dumps(releases).encode() if "/releases" in url else asset_bytes)

    return open_url


def _release(tag: str, *assets: dict, draft: bool = False, published_at: str = "2026-09-01T00:00:00Z") -> dict:
    return {"tag_name": tag, "draft": draft, "published_at": published_at, "assets": list(assets)}


def _archive(destination: Path, *, name: str = "mtproto-proxy", payload: bytes = b"\x7fELF") -> Path:
    source = destination / "member"
    source.write_bytes(payload)
    archive = destination / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(source, arcname=name)
    return archive


def _install(tmp_path: Path, archive: Path | None, *, binary: Path | None = None, on_failure=None, host=None):
    """Run ``download_binary`` against an injected release archive."""

    binary = binary or tmp_path / "bin" / "mtproto-zig"

    def fake_download(_repo, _asset_names, dest, *, timeout=15, on_error=None):
        if archive is None:
            if on_error is not None:
                on_error("в релизах example/repo нет точного архива mtproto-proxy-linux-x86_64.tar.gz")
            return False
        dest.write_bytes(archive.read_bytes())
        return True

    with (
        patch.object(installation, "download_release_asset", side_effect=fake_download),
        patch.object(installation.tempfile, "gettempdir", return_value=str(tmp_path)),
    ):
        installed = installation.download_binary(
            host=host if host is not None else SimpleNamespace(),
            repo="example/repo",
            binary=binary,
            on_failure=on_failure,
        )
    return installed, binary


def test_resolver_follows_the_proxy_asset_beyond_releases_latest():
    """The newest release publishes only mtbuddy assets; the proxy lives one back."""
    releases = [
        _release(
            "v9",
            {"name": "mtbuddy-linux-x86_64.tar.gz", "browser_download_url": "u"},
            published_at="2026-09-20T00:00:00Z",
        ),
        _release("v8", PROXY_ASSET, published_at="2026-09-10T00:00:00Z"),
    ]

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github(releases)):
        tag, asset = downloader.resolve_release_asset("example/repo", ASSET_NAMES)

    assert (tag, asset["name"]) == ("v8", PROXY_ASSET["name"])


def test_resolver_orders_by_publication_time_and_skips_drafts():
    releases = [
        _release("v-old", PROXY_ASSET, published_at="2026-08-01T00:00:00Z"),
        _release("v-draft", PROXY_ASSET, draft=True, published_at="2026-09-30T00:00:00Z"),
        _release("v-new", PROXY_ASSET, published_at="2026-09-15T00:00:00Z"),
    ]

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github(releases)):
        tag, _asset = downloader.resolve_release_asset("example/repo", ASSET_NAMES)

    assert tag == "v-new"


def test_resolver_prefers_the_v3_candidate_inside_one_release():
    releases = [
        _release(
            "v1",
            {"name": "mtproto-proxy-linux-x86_64.tar.gz", "browser_download_url": "generic"},
            {"name": "mtproto-proxy-linux-x86_64_v3.tar.gz", "browser_download_url": "v3"},
        )
    ]

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github(releases)):
        _tag, asset = downloader.resolve_release_asset("example/repo", ASSET_NAMES)

    assert asset["browser_download_url"] == "v3"


def test_resolver_requires_an_exact_asset_name():
    """A sidecar or a differently suffixed asset is not a substitute."""
    releases = [
        _release(
            "v1",
            {"name": "mtproto-proxy-linux-x86_64.tar.gz.sig", "browser_download_url": "sig"},
            {"name": "mtproto-proxy-linux-riscv64.tar.gz", "browser_download_url": "rv"},
        )
    ]

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github(releases)):
        with pytest.raises(ValueError, match="нет точного архива"):
            downloader.resolve_release_asset("example/repo", ASSET_NAMES)


def test_missing_digest_fails_closed_without_downloading(tmp_path, monkeypatch):
    """The emergency unverified flag never applies to a privileged binary."""
    monkeypatch.setenv("HYDRA_ALLOW_UNVERIFIED_DOWNLOADS", "1")
    errors: list[str] = []
    destination = tmp_path / "proxy.tar.gz"

    with (
        patch.object(downloader.urllib.request, "urlopen", side_effect=_github([_release("v1", PROXY_ASSET)])),
        patch.object(downloader, "download") as download,
    ):
        ok = downloader.download_release_asset("example/repo", ASSET_NAMES, destination, on_error=errors.append)

    assert ok is False
    assert errors == [f"Файл {PROXY_ASSET['name']} не содержит SHA-256 digest или sidecar"]
    download.assert_not_called()
    assert not destination.exists()


def test_mismatched_digest_fails_closed_before_extraction(tmp_path):
    payload = b"not-the-declared-payload"
    asset = dict(PROXY_ASSET, digest="sha256:" + "0" * 64)
    errors: list[str] = []
    destination = tmp_path / "proxy.tar.gz"

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github([_release("v1", asset)], payload)):
        ok = downloader.download_release_asset("example/repo", ASSET_NAMES, destination, on_error=errors.append)

    assert ok is False
    assert errors == ["SHA-256 загруженного файла не совпадает с release metadata"]
    assert not destination.exists()


def test_matching_digest_downloads_the_asset(tmp_path):
    payload = b"archive-bytes"
    asset = dict(PROXY_ASSET, digest="sha256:" + hashlib.sha256(payload).hexdigest())
    destination = tmp_path / "proxy.tar.gz"

    with patch.object(downloader.urllib.request, "urlopen", side_effect=_github([_release("v1", asset)], payload)):
        assert downloader.download_release_asset("example/repo", ASSET_NAMES, destination) is True

    assert destination.read_bytes() == payload


def test_release_checksum_sidecar_verifies_an_older_asset(tmp_path):
    payload = b"archive-bytes"
    digest = hashlib.sha256(payload).hexdigest()
    sidecar = {
        "name": PROXY_ASSET["name"] + ".sha256",
        "browser_download_url": "https://example.invalid/a.sha256",
    }
    releases = [_release("v1", PROXY_ASSET, sidecar)]
    destination = tmp_path / "proxy.tar.gz"

    def open_url(request, timeout=None):  # noqa: ARG001 - urlopen signature
        url = getattr(request, "full_url", str(request))
        if "/releases" in url:
            return _Response(json.dumps(releases).encode())
        if url.endswith(".sha256"):
            return _Response(f"{digest}  {PROXY_ASSET['name']}\n".encode())
        return _Response(payload)

    with patch.object(downloader.urllib.request, "urlopen", side_effect=open_url):
        assert downloader.download_release_asset("example/repo", ASSET_NAMES, destination) is True

    assert destination.read_bytes() == payload


def test_download_failure_keeps_the_previous_binary(tmp_path):
    binary = tmp_path / "bin" / "mtproto-zig"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"OLD-BINARY")
    stages: list[str] = []

    installed, _binary = _install(tmp_path, None, binary=binary, on_failure=stages.append)

    assert installed is False
    assert binary.read_bytes() == b"OLD-BINARY"
    assert stages == ["в релизах example/repo нет точного архива mtproto-proxy-linux-x86_64.tar.gz"]


def test_archive_accepts_the_exact_architecture_binary_name(tmp_path):
    archive = _archive(tmp_path, name="mtproto-proxy-linux-x86_64")

    installed, binary = _install(tmp_path, archive)

    assert installed is True
    assert binary.read_bytes() == b"\x7fELF"


def test_archive_without_the_binary_keeps_the_previous_binary(tmp_path):
    archive = tmp_path / "empty.tar.gz"
    other = tmp_path / "readme.txt"
    other.write_text("no proxy here")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(other, arcname="readme.txt")
    binary = tmp_path / "bin" / "mtproto-zig"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"OLD-BINARY")
    stages: list[str] = []

    installed, _binary = _install(tmp_path, archive, binary=binary, on_failure=stages.append)

    assert installed is False
    assert stages == ["в релизном архиве mtproto.zig нет бинарника mtproto-proxy"]
    assert binary.read_bytes() == b"OLD-BINARY"
    assert not binary.with_suffix(".pending").exists()


def test_invalid_tar_keeps_the_previous_binary_and_reports_a_stage(tmp_path):
    archive = tmp_path / "invalid.tar.gz"
    archive.write_bytes(b"not a tar archive")
    binary = tmp_path / "bin" / "mtproto-zig"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"OLD-BINARY")
    stages: list[str] = []

    installed, _binary = _install(tmp_path, archive, binary=binary, on_failure=stages.append)

    assert installed is False
    assert binary.read_bytes() == b"OLD-BINARY"
    assert stages and stages[0].startswith("не удалось распаковать релизный архив mtproto.zig:")


def test_non_elf_payload_keeps_the_previous_binary(tmp_path):
    archive = _archive(tmp_path, payload=b"#!/bin/sh\necho not an elf\n")
    binary = tmp_path / "bin" / "mtproto-zig"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"OLD-BINARY")
    stages: list[str] = []

    installed, _binary = _install(tmp_path, archive, binary=binary, on_failure=stages.append)

    assert installed is False
    assert stages == ["загруженный бинарник mtproto.zig не является исполняемым ELF"]
    assert binary.read_bytes() == b"OLD-BINARY"
    assert not binary.with_suffix(".pending").exists()


def test_binary_is_replaced_atomically_only_after_verification(tmp_path):
    archive = _archive(tmp_path)
    binary = tmp_path / "bin" / "mtproto-zig"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"OLD-BINARY")
    observed: list[bytes] = []
    real_copy = shutil.copy2

    def copy(source, target, *args, **kwargs):
        result = real_copy(source, target, *args, **kwargs)
        observed.append(binary.read_bytes())
        return result

    with patch.object(installation.shutil, "copy2", side_effect=copy):
        installed, _binary = _install(tmp_path, archive, binary=binary)

    assert installed is True
    assert observed == [b"OLD-BINARY"], "the installed binary stays untouched while the replacement is pending"
    assert binary.read_bytes() == b"\x7fELF"
    assert not binary.with_suffix(".pending").exists()


def test_install_failure_reaches_apply_error_with_its_exact_stage():
    stage = "в релизах sleep3r/mtproto.zig нет точного архива mtproto-proxy-linux-x86_64_v3.tar.gz"
    plugin = MtprotoZigPlugin()

    def failed_download(**kwargs) -> bool:
        kwargs["on_failure"](stage)
        return False

    with patch("hydra.plugins.mtproto_zig.plugin.installation.download_binary", side_effect=failed_download):
        assert plugin.install() is False
    assert plugin.install_failure() == stage

    current = {"error": ""}

    def set_error(message: str) -> None:
        current["error"] = message

    def rollback_apply(_state) -> bool:
        current["error"] = ""
        return True

    operations = PluginLifecycleOperations(
        get_plugin=lambda _name: plugin,
        get_protocol=lambda state, name: state.protocols.setdefault(name, PluginState()),
        lifecycle_result=lambda _plugin, _operation, _state=None: False,
        apply_config=rollback_apply,
        save_state=lambda _state: None,
        last_apply_error=lambda: current["error"],
        set_apply_error=set_error,
        log_rollback_error=lambda _message: None,
        invoker=PluginInvoker(),
    )

    assert operations.install(AppState(), "mtproto_zig") is False
    assert current["error"] == f"Установка mtproto_zig: {stage}"
    assert current["error"] != "Ошибка применения конфигурации"


class _RecordingHost:
    """A host double that fails the test if the installer touches the host."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, args, **_kwargs):
        self.commands.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_install_never_delegates_to_upstream_managers_or_the_host(tmp_path):
    """Upstream bootstrap.sh/mtbuddy own another layout: they are never invoked,
    and a verified download mutates no host state of its own."""
    host = _RecordingHost()

    installed, _binary = _install(tmp_path, _archive(tmp_path), host=host)

    assert installed is True
    assert host.commands == []
    assert "import subprocess" not in Path(installation.__file__).read_text(encoding="utf-8")
