"""Host-side installation of the Caddy L4 binary used by the SNI router."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.core.state_models import AppState

NAIVE_FORWARD_PROXY_MODULE = (
    "github.com/caddyserver/forwardproxy@caddy2="
    "github.com/aUsernameWoW/forwardproxy@c55724423ecd39402624538071f198036be79c25"
)
# Upstream forwardproxy without the UoT addition: the build for a server that
# deliberately does not serve UDP over TCP. Same handler and Caddyfile surface,
# so the only difference the operator sees is the missing UoT path.
NAIVE_FORWARD_PROXY_STOCK_MODULE = "github.com/caddyserver/forwardproxy@0aab84dad4fc2830789f34e27b4d7bc22a40889e"

# The Go tarball is unpacked into /tmp before it replaces /usr/local/go: a full /tmp turned that
# into a confusing tar error halfway through an installation that had already downloaded 70 MB.
GO_UNPACK_REQUIRED_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True)
class InstallSettings:
    """Pinned build inputs and filesystem locations for Caddy L4."""

    binary: Path
    caddy_l4_version: str
    go_version: str
    go_releases_url: str
    build_timeout: int
    caddy_version: str = "v2.11.4"


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


def _restore_previous_go(backup_go: Path, current_go: Path) -> None:
    """Put the previous toolchain back when the new one did not survive."""
    if current_go.exists() or not backup_go.exists():
        return
    try:
        shutil.move(str(backup_go), str(current_go))
    except OSError as exc:
        print(f"  Не удалось вернуть прежний Go: {exc}")


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
        f"  Компилятор Go {settings.go_version} не найден: скачиваю официальную сборку Go {settings.go_version}..."
    )
    go_tar = Path(f"/tmp/hydra-go-{os.getpid()}.tar.gz")
    from hydra.utils.net import detect_arch

    architecture = detect_arch()
    go_arch = architecture if architecture in ("amd64", "arm64") else "amd64"
    go_filename = f"go{settings.go_version}.linux-{go_arch}.tar.gz"
    go_url = f"https://go.dev/dl/{go_filename}"

    from hydra.utils.downloader import download

    digest = official_digest(go_filename)
    if not digest:
        print("  Не удалось получить контрольную сумму официального Go из go.dev")
        return False
    # A slow link is not a broken host: the toolchain is about 70 MB and the shared download
    # timeout is two minutes, so the same attempt is made again instead of failing the whole
    # installation on one unlucky transfer.
    downloaded = False
    for attempt in range(1, 4):
        if download(go_url, go_tar, timeout=600, sha256=digest):
            downloaded = True
            break
        print(f"  Загрузка Go не удалась (попытка {attempt} из 3)")
        if attempt < 3:
            time.sleep(5)
    if not downloaded:
        return False

    free_bytes = shutil.disk_usage("/tmp").free
    if free_bytes < GO_UNPACK_REQUIRED_BYTES:
        print(
            "  Недостаточно места в /tmp для распаковки Go: нужно около "
            f"{GO_UNPACK_REQUIRED_BYTES // (1024 * 1024)} МБ, свободно "
            f"{free_bytes // (1024 * 1024)} МБ",
        )
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
        print(f"  Не удалось распаковать Go: {exc}")
        _restore_previous_go(backup_go, current_go)
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
        print(f"  Сборка caddy-l4 не удалась: {exc}")
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
        print("  Скачиваю готовый xcaddy с GitHub...")
        if download_github_asset(
            "caddyserver/xcaddy",
            f"linux_{detect_arch()}.tar.gz",
            xcaddy_tar,
        ):
            try:
                extract_tarball(xcaddy_tar, Path(f"{go_path}/bin"))
                os.chmod(xcaddy_binary, 0o755)
                print("  xcaddy распакован.")
            except Exception as exc:
                print(f"  Не удалось распаковать xcaddy: {exc}")
            finally:
                xcaddy_tar.unlink(missing_ok=True)
        else:
            print("  Не удалось скачать готовый xcaddy.")

    if not os.path.exists(xcaddy_binary):
        # The pinned archive could not be fetched, so this fallback builds whatever the module
        # proxy serves today — a different version from the one the release was tested with.
        print(
            "  Готовый xcaddy недоступен: собираю из исходников, версия не закреплена "
            "(берётся то, что отдаёт прокси модулей)...",
        )
        installed = host.run(
            [
                "go",
                "install",
                "github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
            ],
            capture_output=True,
            env=env,
        )
        if getattr(installed, "returncode", 1) != 0:
            print("  Сборка xcaddy из исходников не удалась")
    if os.path.exists(xcaddy_binary):
        return xcaddy_binary
    resolved = shutil.which("xcaddy")
    if resolved:
        return resolved
    # An empty answer, not the bare name: a build started with a command that does not exist
    # fails with a message nobody can act on.
    return ""


def install(
    state: AppState | None,
    settings: InstallSettings,
    host: Any,
    *,
    force: bool,
    installed: Callable[[], bool],
    ensure_go: Callable[[], bool],
    build: Callable[[list[str], dict[str, str]], Any | None],
    forward_proxy: bool = False,
    forward_proxy_module: str = NAIVE_FORWARD_PROXY_MODULE,
    layer4: bool = True,
    validate: Callable[[Path], bool] | None = None,
) -> bool:
    """Build and atomically install Caddy L4 with required Hydra modules."""
    if installed() and not force:
        return True

    del state  # Naive runs in its own binary, independently of the L4 router.

    print("  Устанавливаю компилятор Go...")
    if not ensure_go():
        print("  Современный компилятор Go поставить не удалось. Пробую установку из apt...")
        host.run(["apt-get", "update"], capture_output=True, timeout=300)
        host.run(
            ["apt-get", "install", "-y", "golang-go"],
            capture_output=True,
            timeout=300,
        )

    print(f"  Устанавливаю xcaddy и собираю {settings.binary.name}...")
    go_path = "/usr/local/share/go"
    try:
        os.makedirs(go_path, exist_ok=True)
    except OSError as exc:
        print(f"  Не удалось подготовить {go_path}: {exc}")
        return False
    env = {**os.environ, "GOPATH": go_path, "GOBIN": f"{go_path}/bin"}
    xcaddy_binary = _ensure_xcaddy_binary(go_path, host, env)
    if not xcaddy_binary:
        print("  xcaddy недоступен, а без него Caddy не собрать")
        return False

    pending_binary = settings.binary.with_suffix(".pending")
    pending_binary.unlink(missing_ok=True)
    base_build = [
        xcaddy_binary,
        "build",
        settings.caddy_version,
    ]
    if layer4:
        base_build += [
            "--with",
            f"github.com/mholt/caddy-l4@{settings.caddy_l4_version}",
            "--with",
            f"github.com/mholt/caddy-l4/modules/l4close@{settings.caddy_l4_version}",
        ]
    build_args = list(base_build)
    if forward_proxy:
        build_args += ["--with", forward_proxy_module]
    build_args += ["--output", str(pending_binary)]

    result = build(build_args, env)
    if result is None:
        return False
    if result.returncode != 0:
        print(f"  Сборка Caddy L4 завершилась с кодом {result.returncode}")
        print(f"  Вывод сборки:\n{result.stderr or result.stdout or ''}")
        return False
    if not pending_binary.exists():
        return False

    modules = host.run(
        [str(pending_binary), "list-modules"],
        capture_output=True,
        text=True,
    )
    required = ["layer4.handlers.proxy", "layer4.handlers.close"] if layer4 else []
    if forward_proxy:
        required.append("http.handlers.forward_proxy")
    if (
        modules.returncode != 0
        or any(name not in modules.stdout for name in required)
    ):
        pending_binary.unlink(missing_ok=True)
        print("  В собранном бинарнике Caddy нет нужных модулей HYDRA")
        return False

    pending_binary.chmod(0o755)
    if validate is not None and not validate(pending_binary):
        pending_binary.unlink(missing_ok=True)
        return False
    if settings.binary.exists():
        shutil.copy2(settings.binary, settings.binary.with_suffix(".previous"))
    pending_binary.replace(settings.binary)
    return True


def _restore_failed_binary(binary: Path, rollback: Path) -> None:
    """Keep the failed binary's place when the swap could not be completed."""
    if rollback.exists() and not binary.exists():
        rollback.replace(binary)


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
        _restore_failed_binary(binary, rollback)
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
