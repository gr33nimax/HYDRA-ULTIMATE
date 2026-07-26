"""Installation, credential lifecycle, and runtime status for WARP."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


def install(
    *,
    host: Any,
    binary: Path,
    profile: Path,
    account: Path,
    log_path: Path = Path("/var/log/hydra/warp_install.log"),
) -> bool:
    if profile.exists() and binary.exists():
        return True

    from hydra.utils.downloader import download_github_asset_filtered, verify_elf
    from hydra.utils.net import detect_arch

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        profile.parent.mkdir(parents=True, exist_ok=True)
        host.run(["pkill", "-9", "wgcf"], capture_output=True)
        if not binary.exists():
            arch = detect_arch()

            def matches_arch(name: str) -> bool:
                return f"linux_{arch}" in name and not name.endswith(".sha256")

            binary.parent.mkdir(parents=True, exist_ok=True)
            if not download_github_asset_filtered("ViRb3/wgcf", matches_arch, binary):
                log_path.write_text(
                    "Failed to download a verified wgcf release asset.\n",
                    encoding="utf-8",
                )
                return False
            if not verify_elf(binary):
                binary.unlink(missing_ok=True)
                log_path.write_text(
                    "Downloaded wgcf asset is not an ELF binary.\n",
                    encoding="utf-8",
                )
                return False
            binary.chmod(0o755)

        if not account.exists():
            result = host.run(
                [str(binary), "register", "--accept-tos"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(profile.parent),
            )
            if result.returncode != 0:
                log_path.write_text(
                    f"wgcf register failed with code {result.returncode}\n"
                    f"Stdout: {result.stdout}\nStderr: {result.stderr}\n",
                    encoding="utf-8",
                )
                return False

        result = host.run(
            [str(binary), "generate"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(profile.parent),
        )
        if result.returncode != 0:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(
                    f"wgcf generate failed with code {result.returncode}\n"
                    f"Stdout: {result.stdout}\nStderr: {result.stderr}\n"
                )
            return False
        return profile.exists()
    except Exception as exc:
        try:
            log_path.write_text(f"Installation exception: {exc}\n", encoding="utf-8")
        except Exception:
            pass
        return False


def remove_local_profile(profile: Path, account: Path) -> None:
    profile.unlink(missing_ok=True)
    account.unlink(missing_ok=True)


def snapshot_local_profile(
    profile: Path,
    account: Path,
) -> tuple[bytes | None, bytes | None]:
    return (
        profile.read_bytes() if profile.exists() else None,
        account.read_bytes() if account.exists() else None,
    )


def restore_local_profile(
    snapshot: tuple[bytes | None, bytes | None],
    *,
    profile: Path,
    account: Path,
    host: Any,
) -> None:
    profile_bytes, account_bytes = snapshot
    remove_local_profile(profile, account)
    if profile_bytes is not None:
        host.atomic_write(profile, profile_bytes, mode=0o600)
    if account_bytes is not None:
        host.atomic_write(account, account_bytes, mode=0o600)


def uninstall(
    *,
    host: Any,
    binary: Path,
    profile: Path,
    account: Path,
    cache: Path,
) -> bool:
    host.run(["pkill", "-9", "wgcf"], capture_output=True)
    remove_local_profile(profile, account)
    if binary.exists():
        binary.unlink()
    try:
        cache.unlink(missing_ok=True)
    except Exception:
        pass
    return True


def status(
    state: PluginStateAccess | None,
    *,
    profile: Path,
    profiles_dir: Path,
    singbox_running: Callable[[], bool],
) -> PluginStatus:
    installed = profile.exists() or any(profiles_dir.glob("*.conf"))
    enabled = False
    running = False
    if state is not None:
        plugin_state = state.protocols.get("warp")
        if plugin_state:
            enabled = plugin_state.enabled
            running = enabled and singbox_running()
    return PluginStatus(installed=installed, enabled=enabled, running=running)


__all__ = [
    "install",
    "remove_local_profile",
    "restore_local_profile",
    "snapshot_local_profile",
    "status",
    "uninstall",
]
