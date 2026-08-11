"""Trusted release and host adapter for transactional kernel replacement."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hydra.core.host import HostBackend
from hydra.core.state_kernel_models import (
    KERNEL_HYDRACORE,
    KERNEL_SINGBOX_EXTENDED,
)
from hydra.services.kernel import KernelRuntimeStatus
from hydra.services.kernel_release_channels import kernel_release_selection
from hydra.utils.downloader import (
    download_github_asset_filtered,
    extract_tarball,
    verify_elf,
)
from hydra.utils.net import detect_arch


@dataclass(frozen=True)
class _ReleaseSpec:
    repository: str
    asset_name: Callable[[str], str]


_TRUSTED_RELEASES = {
    KERNEL_SINGBOX_EXTENDED: _ReleaseSpec(
        "shtorm-7/sing-box-extended",
        lambda arch: rf"^sing-box-.+-linux-{re.escape(arch)}\.tar\.gz$",
    ),
    KERNEL_HYDRACORE: _ReleaseSpec(
        "gr33nimax/hydracore",
        lambda arch: rf"^hydracore-vps-linux-{re.escape(arch)}\.tar\.gz$",
    ),
}

_HYDRACORE_CORE_ID = "io.hydrabox.hydracore"


class _KernelLease:
    _thread_lock = threading.Lock()

    def __init__(self, handle) -> None:
        self._handle = handle
        self._released = False

    @classmethod
    def acquire(cls, path: Path) -> _KernelLease:
        if not cls._thread_lock.acquire(blocking=False):
            raise RuntimeError("another kernel transaction is already running")
        handle = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a+")
            if os.name != "nt":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return cls(handle)
        except Exception:
            if handle is not None:
                handle.close()
            cls._thread_lock.release()
            raise RuntimeError("another kernel transaction is already running") from None

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            if os.name != "nt":
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
        finally:
            self._thread_lock.release()


class _PreparedSwitch:
    def __init__(
        self,
        *,
        runtime: KernelRuntimeStatus,
        rollback: Callable[[], None],
        cleanup: Callable[[], None],
        warn: Callable[[str], None],
        lease: _KernelLease,
    ) -> None:
        self.runtime = runtime
        self._rollback = rollback
        self._cleanup = cleanup
        self._warn = warn
        self._lease = lease
        self._closed = False

    def commit(self) -> None:
        if self._closed:
            return
        try:
            try:
                self._cleanup()
            except Exception as exc:
                self._warn(f"Kernel switch committed; backup cleanup failed: {exc}")
        finally:
            self._closed = True
            self._lease.release()

    def rollback(self) -> None:
        if self._closed:
            return
        try:
            self._rollback()
        finally:
            try:
                try:
                    self._cleanup()
                except Exception as exc:
                    self._warn(f"Kernel rollback finished; backup cleanup failed: {exc}")
            finally:
                self._closed = True
                self._lease.release()


class KernelInfrastructure:
    """Prepare a verified binary while deferring commit to the application service."""

    def __init__(
        self,
        host: HostBackend,
        *,
        binary_path: Path = Path("/usr/local/bin/sing-box"),
        config_path: Path = Path("/etc/sing-box/config.json"),
        lock_path: Path = Path("/run/lock/hydra-kernel.lock"),
        downloader=download_github_asset_filtered,
        arch_reader=detect_arch,
    ) -> None:
        self._host = host
        self._binary_path = binary_path
        self._config_path = config_path
        self._lock_path = lock_path
        self._download = downloader
        self._arch_reader = arch_reader

    @staticmethod
    def _singbox():
        from hydra.core import singbox

        return singbox

    def _run(self, binary: Path, *arguments: str):
        env = os.environ.copy()
        env.update({
            "LEGACY_DNS_SERVERS": "true",
            "ENABLE_DEPRECATED_LEGACY_DNS_SERVERS": "true",
            "ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER": "true",
        })
        return self._host.run(
            [str(binary), *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def _version_output(self, binary: Path) -> str:
        result = self._run(binary, "version")
        if result.returncode != 0:
            raise RuntimeError("kernel candidate failed its version probe")
        return str(result.stdout or "").strip()

    def _capability_payload(self, binary: Path) -> dict:
        result = self._run(binary, "hydra", "capabilities", "--json")
        if result.returncode != 0:
            return {}
        try:
            payload = json.loads(str(result.stdout or ""))
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _normalized_capabilities(payload: dict) -> tuple[str, ...]:
        values: set[str] = set()
        raw = payload.get("capabilities", ())
        if isinstance(raw, list):
            values.update(str(item) for item in raw if isinstance(item, str))
        features = payload.get("features", {})
        if isinstance(features, dict):
            values.update(
                str(name)
                for name, enabled in features.items()
                if enabled is True
            )
        identity = payload.get("identity", {})
        if isinstance(identity, dict) and identity.get("core_id") == _HYDRACORE_CORE_ID:
            values.add("hydracore")
        return tuple(sorted(values))

    @staticmethod
    def _has_hydracore_contract(payload: dict) -> bool:
        identity = payload.get("identity", {})
        features = payload.get("features", {})
        protocols = payload.get("protocols", {})
        modes = protocols.get("call_modes", ()) if isinstance(protocols, dict) else ()
        wire = (
            protocols.get("call_vk_multi_user_wire", {})
            if isinstance(protocols, dict)
            else {}
        )
        return bool(
            isinstance(identity, dict)
            and identity.get("core_id") == _HYDRACORE_CORE_ID
            and identity.get("role") == "vps"
            and isinstance(features, dict)
            and features.get("call_vk_multi_user") is True
            and features.get("call_vk_multi_user_server") is True
            and features.get("call_vk_multi_user_client") is False
            and isinstance(modes, list)
            and modes == ["multi_user"]
            and isinstance(wire, dict)
            and wire.get("min") == 1
            and wire.get("max") == 2
        )

    @classmethod
    def _has_hydracore_debug_contract(cls, payload: dict) -> bool:
        features = payload.get("features", {})
        return bool(
            cls._has_hydracore_contract(payload)
            and isinstance(features, dict)
            and features.get("call_vk_telemetry") is True
        )

    def _inspect_binary(self, binary: Path, *, running: bool) -> KernelRuntimeStatus:
        version_output = self._version_output(binary)
        capability_payload = self._capability_payload(binary)
        identity = capability_payload.get("identity", {})
        core_id = identity.get("core_id") if isinstance(identity, dict) else ""
        if core_id == _HYDRACORE_CORE_ID or "hydracore" in version_output.lower():
            provider = KERNEL_HYDRACORE
        elif "extended" in version_output.lower():
            provider = KERNEL_SINGBOX_EXTENDED
        else:
            provider = "unknown"
        capabilities = self._normalized_capabilities(capability_payload)
        version_line = version_output.splitlines()[0] if version_output else ""
        return KernelRuntimeStatus(
            True,
            running=running,
            provider=provider,
            version=version_line,
            capabilities=capabilities,
            binary_path=str(binary),
        )

    def inspect(self) -> KernelRuntimeStatus:
        singbox = self._singbox()
        binary = singbox._find_singbox()
        if binary is None:
            return KernelRuntimeStatus(False)
        try:
            return self._inspect_binary(binary, running=singbox.is_running())
        except Exception:
            return KernelRuntimeStatus(
                True,
                running=singbox.is_running(),
                provider="unknown",
                binary_path=str(binary),
            )

    def _download_candidate(self, provider: str, channel: str, directory: Path) -> Path:
        spec = _TRUSTED_RELEASES[provider]
        arch = self._arch_reader()
        if arch not in {"amd64", "arm64"}:
            raise ValueError(f"unsupported kernel architecture: {arch}")
        pattern = re.compile(spec.asset_name(arch))
        archive = directory / "kernel.tar.gz"
        errors: list[str] = []
        selection = kernel_release_selection(provider, channel)
        downloaded = self._download(
            spec.repository,
            lambda name: pattern.fullmatch(name) is not None,
            archive,
            include_prerelease=selection.include_prerelease,
            prerelease_tag_marker=selection.prerelease_tag_marker,
            prerelease_exclude_marker=selection.prerelease_exclude_marker,
            require_unique=True,
            require_digest=True,
            on_error=errors.append,
        )
        if not downloaded:
            raise RuntimeError(errors[-1] if errors else "kernel release download failed")
        extracted = directory / "extracted"
        extract_tarball(archive, extracted)
        candidates = [
            path
            for path in extracted.rglob("sing-box")
            if path.is_file() and path.stat().st_size > 1_000_000
        ]
        if len(candidates) != 1 or not verify_elf(candidates[0]):
            raise RuntimeError("release must contain exactly one ELF sing-box binary")
        candidates[0].chmod(0o755)
        return candidates[0]

    def _validate_candidate(
        self,
        candidate: Path,
        provider: str,
        channel: str = "stable",
    ) -> KernelRuntimeStatus:
        status = self._inspect_binary(candidate, running=False)
        if status.provider != provider:
            raise RuntimeError(
                f"release identity mismatch: expected {provider}, got {status.provider}",
            )
        if provider == KERNEL_HYDRACORE:
            payload = self._capability_payload(candidate)
            if not self._has_hydracore_contract(payload):
                raise RuntimeError(
                    "Hydracore must expose exact identity, "
                    "the VPS Calls role, multi_user-only mode, and wire v1..2",
                )
            if channel == "debug" and not self._has_hydracore_debug_contract(payload):
                raise RuntimeError(
                    "Hydracore debug must expose native VK Calls telemetry",
                )
        if self._config_path.exists():
            checked = self._run(candidate, "check", "-c", str(self._config_path))
            if checked.returncode != 0:
                raise RuntimeError("candidate rejected the active configuration")
        return status

    def prepare_switch(self, provider: str, channel: str) -> _PreparedSwitch:
        if provider not in _TRUSTED_RELEASES:
            raise ValueError(f"unsupported kernel provider: {provider}")
        kernel_release_selection(provider, channel)
        lease = _KernelLease.acquire(self._lock_path)
        backup = self._binary_path.with_name(f".{self._binary_path.name}.kernel.bak")
        singbox = self._singbox()
        was_running = singbox.is_running()
        target_existed = self._binary_path.exists()
        finder = getattr(singbox, "_find_singbox", None)
        had_installed_kernel = bool(finder()) if callable(finder) else target_existed
        should_start = was_running or not had_installed_kernel
        mutated = False
        service_stopped = False

        def cleanup() -> None:
            self._host.remove_file(backup, missing_ok=True)

        def rollback() -> None:
            if mutated:
                singbox.stop()
                if target_existed:
                    if not backup.exists():
                        raise RuntimeError("kernel rollback backup is missing")
                    self._host.atomic_copy(backup, self._binary_path, mode=0o755)
                else:
                    self._host.remove_file(self._binary_path, missing_ok=True)
            if was_running and (mutated or service_stopped) and not singbox.start():
                raise RuntimeError("previous kernel was restored but service did not start")

        try:
            cleanup()
            with tempfile.TemporaryDirectory(prefix="hydra-kernel-") as temp:
                candidate = self._download_candidate(provider, channel, Path(temp))
                candidate_status = self._validate_candidate(candidate, provider, channel)
                if target_existed:
                    self._host.atomic_copy(self._binary_path, backup, mode=0o700)
                if was_running:
                    service_stopped = True
                    if not singbox.stop():
                        raise RuntimeError("failed to stop sing-box before kernel replacement")
                self._host.atomic_copy(candidate, self._binary_path, mode=0o755)
                mutated = True
            installed = self._inspect_binary(self._binary_path, running=False)
            if installed.provider != candidate_status.provider:
                raise RuntimeError("installed kernel identity changed after replacement")
            if should_start and not singbox.start():
                raise RuntimeError("new kernel did not become stable")
            runtime = self._inspect_binary(self._binary_path, running=should_start)
            singbox.log("INFO", f"Prepared kernel switch to {provider}")
            return _PreparedSwitch(
                runtime=runtime,
                rollback=rollback,
                cleanup=cleanup,
                warn=lambda message: singbox.log("WARNING", message),
                lease=lease,
            )
        except Exception as switch_error:
            rollback_error: Exception | None = None
            try:
                rollback()
            except Exception as exc:
                rollback_error = exc
            finally:
                try:
                    cleanup()
                except Exception as exc:
                    singbox.log("WARNING", f"Kernel failure cleanup failed: {exc}")
                finally:
                    lease.release()
            if rollback_error is not None:
                raise RuntimeError(
                    f"kernel switch failed and rollback failed: {rollback_error}",
                ) from switch_error
            raise


__all__ = ["KernelInfrastructure"]
