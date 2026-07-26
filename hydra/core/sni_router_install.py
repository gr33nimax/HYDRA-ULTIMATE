"""Host-side installation of the Caddy L4 binary used by the SNI router."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.core.state_models import AppState


@dataclass(frozen=True)
class InstallSettings:
    """Pinned build inputs and filesystem locations for Caddy L4."""

    binary: Path
    caddy_l4_version: str
    go_version: str
    go_releases_url: str
    build_timeout: int


def is_installed(binary: Path) -> bool:
    """Return whether Hydra's Caddy L4 binary is available."""
    return binary.exists() or shutil.which("caddy-l4") is not None


def official_go_digest(
    go_filename: str,
    *,
    releases_url: str,
    urlopen: Callable[..., Any],
) -> str | None:
    """Return the official checksum for a pinned, possibly older Go release."""
    try:
        request = urllib.request.Request(
            releases_url,
            headers={"User-Agent": "HYDRA"},
        )
        with urlopen(request, timeout=15) as response:
            releases = json.loads(response.read())
        for release in releases:
            for file_info in release.get("files", []):
                if file_info.get("filename") == go_filename:
                    return file_info.get("sha256")
    except (OSError, ValueError, TypeError):
        pass
    return None


def ensure_modern_go(
    settings: InstallSettings,
    host: Any,
    *,
    official_digest: Callable[[str], str | None],
) -> bool:
    """Install an official Go toolchain compatible with pinned Caddy L4."""
    os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"
    go_bin = shutil.which("go")
    if go_bin:
        try:
            result = host.run([go_bin, "version"], capture_output=True, text=True)
            if result.returncode == 0:
                parts = result.stdout.split()
                if len(parts) >= 3 and parts[2].startswith("go"):
                    version = [
                        int(value)
                        for value in parts[2][2:].split(".")
                        if value.isdigit()
                    ]
                    if version and tuple((version + [0, 0])[:2]) >= (1, 25):
                        return True
        except Exception:
            pass

    print(
        "  Modern Go compiler (>= 1.25) not found. "
        f"Installing official Go {settings.go_version}..."
    )
    go_tar = Path(f"/tmp/hydra-go-{os.getpid()}.tar.gz")
    from hydra.utils.net import detect_arch

    architecture = detect_arch()
    go_arch = architecture if architecture in ("amd64", "arm64") else "amd64"
    go_filename = f"go{settings.go_version}.linux-{go_arch}.tar.gz"
    go_url = f"https://go.dev/dl/{go_filename}"

    from hydra.utils.downloader import download

    digest = official_digest(go_filename)
    if not (digest and download(go_url, go_tar, sha256=digest)):
        return False

    extract_root = Path(tempfile.mkdtemp(prefix="hydra-go-", dir="/tmp"))
    current_go = Path("/usr/local/go")
    backup_go = Path(f"/usr/local/go.hydra-previous-{os.getpid()}")
    try:
        extracted = host.run(
            ["tar", "-C", str(extract_root), "-xzf", str(go_tar)],
            capture_output=True,
        )
        candidate = extract_root / "go"
        if extracted.returncode != 0 or not (candidate / "bin" / "go").exists():
            return False
        if current_go.exists():
            shutil.move(str(current_go), str(backup_go))
        shutil.move(str(candidate), str(current_go))
        os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"
        check = host.run(
            [str(current_go / "bin" / "go"), "version"],
            capture_output=True,
            text=True,
        )
        if (
            check.returncode == 0
            and f"go{settings.go_version}" in check.stdout
        ):
            return True
        if current_go.exists():
            shutil.move(str(current_go), str(extract_root / "failed-go"))
        if backup_go.exists():
            shutil.move(str(backup_go), str(current_go))
    except Exception as exc:
        print(f"  Failed to extract Go: {exc}")
        if not current_go.exists() and backup_go.exists():
            shutil.move(str(backup_go), str(current_go))
    finally:
        go_tar.unlink(missing_ok=True)
        shutil.rmtree(extract_root, ignore_errors=True)
    return False


def run_caddy_build(
    args: list[str],
    env: dict[str, str],
    *,
    host: Any,
    timeout: int,
) -> Any | None:
    """Run an xcaddy build with enough time for an empty module cache."""
    try:
        return host.run(
            args,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except Exception as exc:
        print(f"  caddy-l4 build failed: {exc}")
        return None


def _ensure_xcaddy_binary(
    go_path: str,
    host: Any,
    env: dict[str, str],
) -> str:
    """Resolve xcaddy, installing it through the bounded fallback chain."""
    xcaddy_binary = f"{go_path}/bin/xcaddy"
    if not os.path.exists(xcaddy_binary):
        from hydra.utils.downloader import download_github_asset, extract_tarball
        from hydra.utils.net import detect_arch

        xcaddy_tar = Path("/tmp/xcaddy.tar.gz")
        print("  Downloading precompiled xcaddy from GitHub...")
        if download_github_asset(
            "caddyserver/xcaddy",
            f"linux_{detect_arch()}.tar.gz",
            xcaddy_tar,
        ):
            try:
                extract_tarball(xcaddy_tar, Path(f"{go_path}/bin"))
                os.chmod(xcaddy_binary, 0o755)
                print("  Successfully downloaded and extracted xcaddy.")
            except Exception as exc:
                print(f"  Failed to extract xcaddy: {exc}")
            finally:
                xcaddy_tar.unlink(missing_ok=True)
        else:
            print("  Downloading precompiled xcaddy failed.")

    if not os.path.exists(xcaddy_binary):
        print(
            "  Trying go install "
            "github.com/caddyserver/xcaddy/cmd/xcaddy@latest...",
        )
        host.run(
            [
                "go",
                "install",
                "github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
            ],
            capture_output=True,
            env=env,
        )
    if os.path.exists(xcaddy_binary):
        return xcaddy_binary
    return shutil.which("xcaddy") or "xcaddy"


def install(
    state: AppState | None,
    settings: InstallSettings,
    host: Any,
    *,
    force: bool,
    installed: Callable[[], bool],
    ensure_go: Callable[[], bool],
    build: Callable[[list[str], dict[str, str]], Any | None],
) -> bool:
    """Build and atomically install Caddy L4 with required Hydra modules."""
    if installed() and not force:
        return True

    need_naive_forward_proxy = False
    if state:
        naive = state.protocols.get("naive")
        need_naive_forward_proxy = bool(naive and naive.enabled)

    print("  Installing Go compiler...")
    if not ensure_go():
        print("  Failed to install a modern Go compiler. Trying apt fallback...")
        host.run(["apt-get", "update"], capture_output=True, timeout=300)
        host.run(
            ["apt-get", "install", "-y", "golang-go"],
            capture_output=True,
            timeout=300,
        )

    print("  Installing xcaddy and building caddy-l4...")
    go_path = "/usr/local/share/go"
    os.makedirs(go_path, exist_ok=True)
    env = {**os.environ, "GOPATH": go_path, "GOBIN": f"{go_path}/bin"}
    xcaddy_binary = _ensure_xcaddy_binary(go_path, host, env)

    pending_binary = settings.binary.with_suffix(".pending")
    pending_binary.unlink(missing_ok=True)
    base_build = [
        xcaddy_binary,
        "build",
        "--with",
        f"github.com/mholt/caddy-l4@{settings.caddy_l4_version}",
        "--with",
        (
            "github.com/mholt/caddy-l4/modules/l4close@"
            f"{settings.caddy_l4_version}"
        ),
    ]
    build_args = list(base_build)
    if need_naive_forward_proxy:
        build_args += [
            "--with",
            (
                "github.com/caddyserver/forwardproxy@caddy2="
                "github.com/Michaol/forwardproxy-naive@caddy2"
            ),
        ]
    build_args += ["--output", str(pending_binary)]

    result = build(build_args, env)
    if result is None:
        return False
    if result.returncode != 0 and need_naive_forward_proxy:
        result = build(
            [
                *base_build,
                "--with",
                "github.com/caddyserver/forwardproxy@caddy2",
                "--output",
                str(pending_binary),
            ],
            env,
        )
        if result is None:
            return False
    if result.returncode != 0 and need_naive_forward_proxy:
        result = build(
            [*base_build, "--output", str(pending_binary)],
            env,
        )
        if result is None:
            return False
    if result.returncode != 0:
        print(f"  [Caddy L4 build error] return code: {result.returncode}")
        print(f"  Error output:\n{result.stderr or result.stdout or ''}")
        return False
    if not pending_binary.exists():
        return False

    modules = host.run(
        [str(pending_binary), "list-modules"],
        capture_output=True,
        text=True,
    )
    required = ["layer4.handlers.proxy", "layer4.handlers.close"]
    if need_naive_forward_proxy:
        required.append("http.handlers.forward_proxy")
    if (
        modules.returncode != 0
        or any(name not in modules.stdout for name in required)
    ):
        pending_binary.unlink(missing_ok=True)
        print("  Built Caddy binary is missing required Hydra modules")
        return False

    pending_binary.chmod(0o755)
    if settings.binary.exists():
        shutil.copy2(settings.binary, settings.binary.with_suffix(".previous"))
    pending_binary.replace(settings.binary)
    return True


def restore_previous_binary(binary: Path) -> bool:
    """Restore the last successfully installed Caddy binary."""
    backup = binary.with_suffix(".previous")
    if not backup.exists():
        return False
    rollback = binary.with_suffix(".failed")
    try:
        if binary.exists():
            binary.replace(rollback)
        shutil.copy2(backup, binary)
        binary.chmod(0o755)
        rollback.unlink(missing_ok=True)
        return True
    except OSError:
        if rollback.exists() and not binary.exists():
            rollback.replace(binary)
        return False


__all__ = [
    "InstallSettings",
    "ensure_modern_go",
    "install",
    "is_installed",
    "official_go_digest",
    "restore_previous_binary",
    "run_caddy_build",
]
