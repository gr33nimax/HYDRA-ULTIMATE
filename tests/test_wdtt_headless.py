"""Contract tests for the qWDTT VK headless-creator integration."""
from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.wdtt import headless
from hydra.plugins.wdtt.model import HEADLESS_COOKIES_FILE, WdttEnvironment
from hydra.ui.plugin_managers._wdtt_install import _client_link
from hydra.ui.plugin_managers import wdtt as wdtt_facade
from hydra.ui.plugin_managers._facade_bridge import bind_facade


class _Host:
    def __init__(self) -> None:
        self.writes: list[tuple[Path, int]] = []
        self.directories: list[tuple[Path, int]] = []

    def atomic_write(self, path: Path, content: str | bytes, *, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        self.writes.append((path, mode))

    def ensure_directory(self, path: Path, *, mode: int) -> None:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
        self.directories.append((path, mode))

    def which(self, value: str) -> str | None:
        return value if Path(value).exists() else None

    def run(self, *_args, **_kwargs):
        return SimpleNamespace(returncode=0)


def _env(tmp_path: Path) -> WdttEnvironment:
    headless_dir = tmp_path / "headless"
    return WdttEnvironment(
        host=_Host(),
        bin_path=tmp_path / "wdtt-server",
        config_dir=tmp_path,
        config_file=tmp_path / "config.json",
        passwords_file=tmp_path / "passwords.json",
        headless_dir=headless_dir,
        headless_cookies_file=headless_dir / "cookies-vk.json",
        headless_link_file=tmp_path / "qwdtt_link.txt",
        headless_state_file=headless_dir / "state.json",
        headless_bin_path=tmp_path / "headless-vk-creator",
        headless_service_file=tmp_path / "wdtt-headless@.service",
        headless_call_count=4,
        headless_github_repo="kulikov0/whitelist-bypass",
        service_file=tmp_path / "wdtt.service",
        service_name="wdtt",
        default_dtls_port=56000,
        default_wg_port=56001,
        default_wg_subnet="10.66.66.0/16",
        wg_interface="wdtt0",
        wg_stats_dir=tmp_path / "stats",
        local_tun_port=9000,
        system_password="master",
        github_repo="repo",
        source_url="https://example.invalid/source",
        go_dl_url="https://example.invalid/go",
        source_extract_timeout=1,
        go_module_timeout=1,
        go_build_timeout=1,
        json_module=__import__("json"),
        os_module=__import__("os"),
        platform_module=SimpleNamespace(machine=lambda: "x86_64"),
        re_module=__import__("re"),
        shutil_module=SimpleNamespace(which=lambda _value: None),
        tempfile_module=SimpleNamespace(),
        time_module=SimpleNamespace(sleep=lambda _seconds: None),
        urllib_module=SimpleNamespace(),
        firewall_module=SimpleNamespace(),
        local_ip=lambda: "203.0.113.10",
        public_ip=lambda: "203.0.113.10",
    )


def _state() -> AppState:
    return AppState(
        network=SimpleNamespace(
            server_ip="203.0.113.10",
            domain="",
            sub_domain="",
            dns_servers=[],
            dnscrypt_port=5300,
            tproxy_enabled=False,
            tproxy_port=1081,
            clash_api_enabled=False,
            clash_api_port=9090,
            clash_api_secret="",
        ),
        protocols={
            "wdtt": PluginState(
                enabled=True,
                config={
                    "headless_enabled": True,
                    "dtls_port": 56000,
                    "main_password": "master",
                },
            ),
        },
    )


def test_default_cookie_file_uses_fixed_hydra_directory() -> None:
    assert HEADLESS_COOKIES_FILE.as_posix() == "/etc/hydra/cookiesvk/cookies-vk.json"


def test_manual_artifact_query_returns_only_the_current_master_link(
    tmp_path: Path,
) -> None:
    env = _env(tmp_path)
    env.headless_link_file.write_text(
        "qwdtt://config?pass=master\n",
        encoding="utf-8",
    )

    class Plugin(headless.WdttHeadlessMixin):
        @staticmethod
        def _wdtt_env() -> WdttEnvironment:
            return env

    assert Plugin().manual_client_artifacts(state=_state()) == [
        {
            "profile_name": "master",
            "profile_label": "Master · общая для всех пользователей",
            "links": ["qwdtt://config?pass=master"],
        },
    ]


def test_build_link_requires_four_unique_hashes() -> None:
    link = headless.build_qwdtt_link(
        "203.0.113.10", 56000, "master", ["a", "b", "c", "d"],
    )
    assert "hashes=a,b,c,d" in link
    assert "pass=master" in link
    with pytest.raises(ValueError):
        headless.build_qwdtt_link("203.0.113.10", 56000, "master", ["a"])
    with bind_facade(wdtt_facade):
        assert "hashes=a,b,c,d" in _client_link(
            "203.0.113.10", 56000, "master", vk_hash=["a", "b", "c", "d"],
        )


@pytest.mark.parametrize(
    ("machine", "asset_arch", "member"),
    [
        ("x86_64", "x64", "headless-vk-creator"),
        ("aarch64", "arm", "arm64/headless-vk-creator"),
        ("armv7l", "arm", "arm/headless-vk-creator"),
        ("mips64le", "mips", "mips64le/headless-vk-creator"),
    ],
)
def test_release_layout_selects_upstream_bundle(
    machine: str,
    asset_arch: str,
    member: str,
) -> None:
    assert headless._release_layout(machine) == (asset_arch, member)


def test_install_downloads_verified_bundle_and_creates_cookie_dir(tmp_path: Path) -> None:
    env = _env(tmp_path)

    def download(repo: str, matches, destination: Path) -> bool:
        assert repo == "kulikov0/whitelist-bypass"
        assert matches("whitelist-bypass-cli-linux-x64.zip") is True
        with zipfile.ZipFile(destination, "w") as bundle:
            bundle.writestr("headless-vk-creator", b"\x7fELFcreator")
        return True

    with patch.object(
        headless,
        "download_github_asset_filtered",
        side_effect=download,
    ):
        ok, message = headless.install(env)

    assert ok is True
    assert message == "headless creator installed"
    assert env.headless_bin_path.read_bytes() == b"\x7fELFcreator"
    assert (env.headless_bin_path, 0o755) in env.host.writes
    assert (env.headless_dir, 0o700) in env.host.directories


def test_install_rejects_release_without_creator_binary(tmp_path: Path) -> None:
    env = _env(tmp_path)

    def download(_repo: str, _matches, destination: Path) -> bool:
        with zipfile.ZipFile(destination, "w") as bundle:
            bundle.writestr("unexpected", b"\x7fELFother")
        return True

    with patch.object(
        headless,
        "download_github_asset_filtered",
        side_effect=download,
    ):
        ok, message = headless.install(env)

    assert ok is False
    assert "missing from release archive" in message
    assert env.headless_bin_path.exists() is False
    assert (env.headless_dir, 0o700) in env.host.directories


def test_install_rejects_unsupported_architecture_before_download(tmp_path: Path) -> None:
    env = _env(tmp_path)
    env = replace(
        env,
        platform_module=SimpleNamespace(machine=lambda: "ppc64le"),
    )
    with patch.object(headless, "download_github_asset_filtered") as download:
        ok, message = headless.install(env)

    assert ok is False
    assert "unsupported headless creator architecture" in message
    download.assert_not_called()


def test_uninstall_removes_tui_installed_binary(tmp_path: Path) -> None:
    env = _env(tmp_path)
    env.headless_bin_path.write_bytes(b"\x7fELFcreator")
    env.headless_service_file.write_text("unit", encoding="utf-8")
    env.headless_cookies_file.parent.mkdir(parents=True)
    env.headless_cookies_file.write_text("[]", encoding="utf-8")

    headless.uninstall(env)

    assert env.headless_bin_path.exists() is False
    assert env.headless_service_file.exists() is False
    assert env.headless_cookies_file.exists() is False


def test_normalize_cookies_accepts_exported_cookie_file(tmp_path: Path) -> None:
    env = _env(tmp_path)
    cookie_file = tmp_path / "cookies.json"
    cookie_file.write_text('[{"name": "remixsid", "value": "secret"}]', encoding="utf-8")
    normalized = headless.normalize_cookies(str(cookie_file), env)
    assert '"remixsid"' in normalized


def test_setup_writes_cookies_securely_and_updates_one_master_link(tmp_path: Path) -> None:
    env = _env(tmp_path)
    state = _state()
    binary = env.headless_bin_path
    binary.write_bytes(b"\x7fELFcreator")
    env.headless_cookies_file.parent.mkdir(parents=True)
    env.headless_cookies_file.write_text(
        '[\n  {"name": "remixsid", "value": "secret"}\n]\n',
        encoding="utf-8",
    )
    with patch.object(headless, "_wait_hashes", return_value=["a", "b", "c", "d"]):
        ok, message = headless.setup(env, state)

    assert ok is True
    assert "master link" in message
    assert (env.headless_cookies_file, 0o600) in env.host.writes
    assert env.headless_link_file.read_text(encoding="utf-8").count("qwdtt://") == 1
    assert "secret" not in env.headless_link_file.read_text(encoding="utf-8")
    assert env.headless_link_file.read_text(encoding="utf-8").endswith("pass=master\n")
    assert env.headless_state_file.exists()


def test_setup_creates_default_cookie_dir_and_reports_missing_file(tmp_path: Path) -> None:
    env = _env(tmp_path)

    ok, message = headless.setup(env, _state())

    assert ok is False
    assert message == f"VK cookies file is missing: {env.headless_cookies_file}"
    assert (env.headless_cookies_file.parent, 0o700) in env.host.directories


def test_due_is_daily_and_disabled_without_setup(tmp_path: Path) -> None:
    env = _env(tmp_path)
    state = _state()
    assert headless.due(env, state=state) is True
    env.headless_state_file.parent.mkdir(parents=True)
    env.headless_state_file.write_text(
        '{"refreshed_at": "2099-01-01T00:00:00+00:00"}',
        encoding="utf-8",
    )
    assert headless.due(env, state=state) is False
    state.protocols["wdtt"].config["headless_enabled"] = False
    assert headless.due(env, state=state) is False


def test_due_detects_creator_restart_before_daily_deadline(tmp_path: Path) -> None:
    env = _env(tmp_path)
    state = _state()
    env.headless_state_file.parent.mkdir(parents=True)
    env.headless_state_file.write_text(
        '{"hashes": ["a", "b", "c", "d"], '
        '"refreshed_at": "2099-01-01T00:00:00+00:00"}',
        encoding="utf-8",
    )
    for index, call_hash in enumerate(["w", "x", "y", "z"], start=1):
        (env.headless_dir / f"{index}.call.txt").write_text(
            f"https://vk.com/call/join/{call_hash}\n",
            encoding="utf-8",
        )

    assert headless.due(env, state=state) is True


def test_refresh_failure_keeps_previous_master_link(tmp_path: Path) -> None:
    env = _env(tmp_path)
    state = _state()
    env.headless_bin_path.write_bytes(b"\x7fELFcreator")
    env.headless_link_file.write_text("qwdtt://old\n", encoding="utf-8")
    with patch.object(headless, "_wait_hashes", return_value=[]):
        ok, _message = headless._refresh(env, state)

    assert ok is False
    assert env.headless_link_file.read_text(encoding="utf-8") == "qwdtt://old\n"


def test_status_redacts_secret_link(tmp_path: Path) -> None:
    env = _env(tmp_path)
    env.headless_link_file.write_text("qwdtt://secret\n", encoding="utf-8")
    projection = headless.status(env, _state())

    assert projection["link_ready"] is True
    assert "link" not in projection
    assert "hashes" not in projection


def test_wait_hashes_rejects_partially_refreshed_calls(tmp_path: Path) -> None:
    env = _env(tmp_path)
    with patch.object(
        headless,
        "_read_hashes",
        side_effect=[["new-a", "b", "c", "d"], ["w", "x", "y", "z"]],
    ) as read_hashes:
        hashes = headless._wait_hashes(env, previous=["a", "b", "c", "d"])

    assert hashes == ["w", "x", "y", "z"]
    assert read_hashes.call_count == 2


def test_setup_failure_restores_previous_cookies(tmp_path: Path) -> None:
    env = _env(tmp_path)
    state = _state()
    env.headless_cookies_file.parent.mkdir(parents=True)
    original = '[\n  {"name": "remixsid", "value": "old-secret"}\n]\n'
    env.headless_cookies_file.write_text(original, encoding="utf-8")
    with (
        patch.object(headless, "install", return_value=(True, "installed")),
        patch.object(headless, "_refresh", return_value=(False, "failed")),
    ):
        ok, _message = headless.setup(env, state)

    assert ok is False
    assert env.headless_cookies_file.read_text(encoding="utf-8") == original


def test_tui_setup_persists_flag_and_uses_application_ports() -> None:
    state = _state()
    state.protocols["wdtt"].config["headless_enabled"] = False
    app = SimpleNamespace(
        admin=SimpleNamespace(save_state=MagicMock()),
        plugin_action=MagicMock(return_value=(True, "updated")),
        plugin_query=MagicMock(return_value="qwdtt://master-link"),
    )
    with (
        patch.object(wdtt_facade, "clear"),
        patch.object(wdtt_facade, "title"),
        patch.object(wdtt_facade, "panel"),
        patch.object(wdtt_facade, "info"),
        patch.object(wdtt_facade, "success"),
        patch.object(wdtt_facade, "prompt", return_value="") as prompt,
        patch.object(wdtt_facade, "_save_link_to_file") as save_link,
    ):
        wdtt_facade._setup_headless_creator(state, app)

    assert state.protocols["wdtt"].config["headless_enabled"] is True
    app.admin.save_state.assert_called_once_with(state)
    app.plugin_action.assert_called_once_with(
        "wdtt",
        "setup_headless_creator",
        state=state,
    )
    app.plugin_query.assert_called_once_with("wdtt", "headless_creator_link")
    save_link.assert_called_once_with("qwdtt://master-link", "qwdtt_link.txt", app)
    prompt.assert_called_once_with("Нажмите Enter...")


def test_tui_setup_rolls_back_flag_on_runtime_failure() -> None:
    state = _state()
    state.protocols["wdtt"].config["headless_enabled"] = False
    app = SimpleNamespace(
        admin=SimpleNamespace(save_state=MagicMock()),
        plugin_action=MagicMock(return_value=(False, "creator failed")),
        plugin_query=MagicMock(),
    )
    with (
        patch.object(wdtt_facade, "clear"),
        patch.object(wdtt_facade, "title"),
        patch.object(wdtt_facade, "panel"),
        patch.object(wdtt_facade, "info"),
        patch.object(wdtt_facade, "error"),
        patch.object(wdtt_facade, "prompt", return_value="") as prompt,
    ):
        wdtt_facade._setup_headless_creator(state, app)

    assert state.protocols["wdtt"].config["headless_enabled"] is False
    assert app.admin.save_state.call_count == 2
    app.plugin_query.assert_not_called()
    prompt.assert_called_once_with("Нажмите Enter...")
