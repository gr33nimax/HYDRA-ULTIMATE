"""Protected technical probe identity and real, isolated sing-box client probes."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import tempfile
import shutil
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hydra.contracts.managed_node_models import ApplyReceipt
from hydra.contracts.managed_node_observations import CheckResult
from hydra.contracts.managed_node_probe import ProbeMaterial, ProbeMaterials
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, User

_SUPPORTED_CLIENTS = {"vless", "anytls"}


class ManagedNodeProbeIdentityStore:
    """Keep a stable, private technical UUID outside users and desired state."""

    def __init__(self, *, host: HostBackend, root: Path, node_id: str) -> None:
        if (
            not root.is_absolute()
            or not node_id
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in node_id)
        ):
            raise ValueError("managed-node probe identity scope is invalid")
        self._host = host
        self._path = root / "probe-identity.json"
        self._node_id = node_id

    @property
    def node_id(self) -> str:
        return self._node_id

    def ensure(self) -> User:
        if self._path.parent.is_symlink() or self._path.is_symlink():
            raise ValueError("managed-node probe identity path is unsafe")
        self._host.ensure_directory(self._path.parent, mode=0o700)
        if self._path.exists():
            raw = self._read()
            if not isinstance(raw, dict) or set(raw) != {"node_id", "uuid"} or raw["node_id"] != self._node_id:
                raise ValueError("managed-node probe identity does not match this node")
            identity = str(uuid.UUID(raw["uuid"]))
        else:
            identity = str(uuid.uuid4())
            self._host.atomic_write(
                self._path,
                json.dumps({"node_id": self._node_id, "uuid": identity}, sort_keys=True, separators=(",", ":")),
                mode=0o600,
                durable=True,
            )
        return self._user(identity)

    def runtime_users(self) -> list[User]:
        return [self.user()]

    def user(self) -> User:
        if self._path.parent.is_symlink() or self._path.is_symlink() or not self._path.is_file():
            raise ValueError("managed-node technical probe identity is unavailable")
        raw = self._read()
        if not isinstance(raw, dict) or set(raw) != {"node_id", "uuid"} or raw["node_id"] != self._node_id:
            raise ValueError("managed-node probe identity does not match this node")
        return self._user(str(uuid.UUID(raw["uuid"])))

    def cleanup(self) -> None:
        if self._path.parent.is_symlink() or self._path.is_symlink():
            raise ValueError("managed-node probe identity path is unsafe")
        self._host.remove_file(self._path, missing_ok=True)

    def _read(self) -> dict[str, Any]:
        metadata = self._path.stat()
        if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError("managed-node probe identity permissions are unsafe")
        return json.loads(self._host.read_bytes(self._path, max_bytes=1024).decode("utf-8"))

    def _user(self, identity: str) -> User:
        return User(email=f"probe-{self._node_id}@invalid.hydra", uuid=identity)


class ManagedNodeProbeMaterialProvider:
    def __init__(self, *, node_id: str, identity: ManagedNodeProbeIdentityStore, protocols: Any) -> None:
        self._node_id = node_id
        self._identity = identity
        self._protocols = protocols

    def materials(self, state: AppState, receipt: ApplyReceipt) -> ProbeMaterials:
        technical_user = self._identity.user()
        result: list[ProbeMaterial] = []
        for name in sorted(_SUPPORTED_CLIENTS):
            desired = state.protocols.get(name)
            if desired is None or not desired.enabled:
                continue
            raw = self._protocols.singbox_client_config(state, name, technical_user)
            try:
                document = json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} technical client material is unavailable") from exc
            outbound = next(
                (item for item in document.get("outbounds", []) if isinstance(item, dict) and item.get("type") == name),
                None,
            )
            if outbound is None:
                raise ValueError(f"{name} technical client material is unavailable")
            material = ProbeMaterial(name, outbound)
            material.validate()
            result.append(material)
        bundle = ProbeMaterials(self._node_id, receipt, result)
        bundle.validate()
        return bundle


class ManagedNodeProbeClient:
    """Run only a locally rendered, loopback-proxied client within one deadline."""

    def __init__(
        self,
        *,
        host: HostBackend,
        binary: str = "sing-box",
        target_url: str = "https://www.gstatic.com/generate_204",
        expected_status: int = 204,
    ) -> None:
        if not target_url.startswith("https://") or type(expected_status) is not int:
            raise ValueError("managed-node probe target is invalid")
        self._host = host
        self._binary = binary
        self._target = target_url
        self._expected_status = expected_status

    def probe_client(self, material: ProbeMaterial, *, node_id: str, deadline: float) -> CheckResult:
        checked_at = datetime.now(timezone.utc).isoformat()
        if material.protocol not in _SUPPORTED_CLIENTS:
            return CheckResult(
                "connection",
                node_id,
                "not_applicable",
                checked_at,
                stage="capability",
                reason="no compatible client is declared",
            )
        try:
            material.validate()
        except ValueError:
            return CheckResult(
                "connection",
                node_id,
                "unknown",
                checked_at,
                stage="material",
                reason="technical client material is invalid",
            )
        target = self._target_status(deadline)
        if target is not None:
            return CheckResult(
                "connection",
                node_id,
                "unknown",
                checked_at,
                stage="target",
                reason="independent probe target is unavailable",
            )
        binary = self._host.which(self._binary)
        if binary is None:
            return CheckResult(
                "connection",
                node_id,
                "unknown",
                checked_at,
                stage="client",
                reason="compatible sing-box client is unavailable",
            )
        return self._run_client(material, node_id=node_id, binary=binary, deadline=deadline, checked_at=checked_at)

    def _run_client(
        self, material: ProbeMaterial, *, node_id: str, binary: str, deadline: float, checked_at: str
    ) -> CheckResult:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        listener.close()
        tag = str(material.client_config.get("tag") or material.protocol)
        configuration = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [material.client_config, {"type": "direct", "tag": "direct"}],
            "route": {"final": tag, "auto_detect_interface": True},
        }
        process = None
        config_path: Path | None = None
        directory: Path | None = None
        try:
            directory = Path(tempfile.mkdtemp(prefix="hydra-node-probe-"))
            config_path = directory / "client.json"
            self._host.atomic_write(
                config_path, json.dumps(configuration, separators=(",", ":")), mode=0o600, durable=True
            )
            check = self._host.run([binary, "check", "-c", str(config_path)], timeout=_remaining(deadline), text=True)
            if check.returncode != 0:
                return CheckResult(
                    "connection",
                    node_id,
                    "error",
                    checked_at,
                    stage="client_config",
                    reason="sing-box rejected the rendered client configuration",
                )
            process = self._host.popen(
                [binary, "run", "-c", str(config_path)],
                timeout=_remaining(deadline),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not self._wait_listener(port, process, deadline):
                return CheckResult(
                    "connection",
                    node_id,
                    "error",
                    checked_at,
                    stage="client_start",
                    reason="sing-box client did not start before the deadline",
                )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"})
            )
            try:
                response = opener.open(self._target, timeout=_remaining(deadline))
                status = response.status
                response.close()
            except (OSError, TimeoutError, urllib.error.URLError):
                return CheckResult(
                    "connection",
                    node_id,
                    "error",
                    checked_at,
                    stage="client_request",
                    reason="protocol client request failed",
                )
            outcome = "ok" if status == self._expected_status else "error"
            return CheckResult(
                "connection",
                node_id,
                outcome,
                checked_at,
                stage="client_response",
                reason="" if outcome == "ok" else "probe response did not match the expected status",
            )
        except (OSError, TimeoutError):
            return CheckResult(
                "connection",
                node_id,
                "unknown",
                checked_at,
                stage="client",
                reason="real protocol client could not complete within the deadline",
            )
        finally:
            stopped = process is None or _stop_process(process)
            if stopped and config_path is not None and config_path.exists() and not config_path.is_symlink():
                try:
                    self._host.remove_file(config_path, missing_ok=True)
                except OSError:
                    pass
            if directory is not None and stopped:
                shutil.rmtree(directory, ignore_errors=True)

    def _target_status(self, deadline: float) -> int | None:
        try:
            direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            response = direct.open(self._target, timeout=min(3.0, _remaining(deadline)))
            status = response.status
            response.close()
            return status if status != self._expected_status else None
        except (OSError, TimeoutError, urllib.error.URLError):
            return 0

    @staticmethod
    def _wait_listener(port: int, process: Any, deadline: float) -> bool:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=min(0.1, _remaining(deadline))):
                    return True
            except OSError:
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        return False


def _remaining(deadline: float) -> float:
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("probe deadline expired")
    return remaining


def _stop_process(process: Any) -> bool:
    try:
        if process.poll() is not None:
            return True
        process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)
        return process.poll() is not None
    except (OSError, subprocess.TimeoutExpired):
        return False


__all__ = [
    "ManagedNodeProbeClient",
    "ManagedNodeProbeIdentityStore",
    "ManagedNodeProbeMaterialProvider",
]
