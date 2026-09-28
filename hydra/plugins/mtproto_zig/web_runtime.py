"""Runtime staging for the Hydra-owned mtproto.zig WEB relay.

The relay is a second systemd unit running ``mtproto-zig web-relay`` from the
same verified binary and reading the same single Hydra-owned configuration. The
managed frontend terminates TLS and forwards the decrypted HTTP/WebSocket stream
to this loopback listener, so the relay itself never needs the public port.

End-to-end readiness — certificate, route, bridge page and the authenticated
WebSocket upgrade — lives in :mod:`hydra.plugins.mtproto_zig.bridge_probe`.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hydra.utils.commands import bounded_reason

from .bridge_probe import PROBE_TIMEOUT_SECONDS
from .constants import WEB_RELAY_PORT, WEB_WS_PATH
from .installation import report_stage, write_web_service
from .runtime import READY_POLLS, ready_probe, service_state


def snapshot(*, service_file: Path, running: bool) -> dict:
    """Capture the relay unit and its running state before apply."""
    return {
        "unit": service_file.read_bytes() if service_file.exists() else None,
        "running": running,
    }


def rollback(
    previous: dict | None,
    *,
    host: Any,
    service: str,
    service_file: Path,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Restore the captured relay unit and running state.

    A rollback to "no relay" is a stop: ``systemctl disable --now`` must run
    while the unit file still exists, because ``disable`` reads ``[Install]``
    from it to drop the enable symlink. Removing the file first would leave the
    symlink behind, turn the failed disable into a false rollback failure, and
    let ``PartOf=`` pull a WEB-less relay up together with the main service.
    """
    content = (previous or {}).get("unit")
    if content is None:
        return stop(host=host, service=service, service_file=service_file, on_failure=on_failure)
    service_file.parent.mkdir(parents=True, exist_ok=True)
    service_file.write_bytes(content)
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    action = "restart" if (previous or {}).get("running") else "disable"
    if action == "disable":
        return host.run(["systemctl", "disable", "--now", service], capture_output=True).returncode == 0
    return host.run(["systemctl", action, service], capture_output=True).returncode == 0


def running(host: Any, service: str) -> bool:
    state, _result = service_state(host, service)
    return state == "active"


def apply(
    *,
    host: Any,
    binary: Path,
    config_file: Path,
    work_dir: Path,
    service: str,
    service_file: Path,
    proxy_service: str,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Install, start and verify the loopback relay before it is advertised."""
    if not write_web_service(
        host=host,
        service_file=service_file,
        binary=binary,
        config=config_file,
        work_dir=work_dir,
        service=service,
        proxy_service=proxy_service,
        on_failure=on_failure,
    ):
        return False
    for action in ("enable", "restart"):
        result = host.run(["systemctl", action, service], capture_output=True, text=True)
        if result.returncode != 0:
            reason = bounded_reason(result)
            suffix = f": {reason}" if reason else ""
            report_stage(on_failure, f"systemctl {action} не выполнился для {service}{suffix}")
            return False
    state, result = service_state(host, service, polls=READY_POLLS)
    if state != "active":
        reason = bounded_reason(result)
        suffix = f" ({reason})" if reason else ""
        report_stage(
            on_failure,
            f"служба {service} не запустилась (state={state or 'unknown'}): смотрите journalctl -u {service}{suffix}",
        )
        return False
    healthy, reason = ready_probe(probe_local)
    if not healthy:
        report_stage(on_failure, f"WEB-релей не отвечает на 127.0.0.1:{WEB_RELAY_PORT}: {reason}")
        return False
    return True


def stop(
    *,
    host: Any,
    service: str,
    service_file: Path,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Remove the relay when the desired mode no longer serves WEB links.

    ``systemctl disable --now`` runs first and regardless of the unit file: a
    unit file removed earlier can leave the enable symlink behind, and that
    surviving link pulls the relay back in at boot once the file returns. A unit
    that never existed is not a failure; a failed disable of a known unit and
    any surviving enable link are reported instead of a clean stop.
    """
    result = host.run(["systemctl", "disable", "--now", service], capture_output=True, text=True)
    existed = service_file.exists()
    service_file.unlink(missing_ok=True)
    reload_result = host.run(["systemctl", "daemon-reload"], capture_output=True, text=True)
    enable_link = service_file.parent / "multi-user.target.wants" / f"{service}.service"
    if enable_link.exists() or enable_link.is_symlink():
        report_stage(on_failure, f"WEB-релей {service} остался включён в multi-user.target.wants")
        return False
    if result.returncode != 0 and existed:
        reason = bounded_reason(result)
        suffix = f": {reason}" if reason else ""
        report_stage(on_failure, f"systemctl disable --now не выполнился для {service}{suffix}")
        return False
    if reload_result.returncode != 0:
        reason = bounded_reason(reload_result)
        suffix = f": {reason}" if reason else ""
        report_stage(on_failure, f"systemctl daemon-reload не выполнился после удаления {service}{suffix}")
        return False
    return True


def probe_local(
    *,
    address: str = "127.0.0.1",
    port: int = WEB_RELAY_PORT,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    """Verify the same-origin HTTP endpoint answers on loopback."""
    request = f"GET {WEB_WS_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((address, port), timeout=timeout) as connection:
            connection.sendall(request.encode())
            answer = connection.recv(64)
    except (OSError, ValueError) as exc:
        reason = str(exc)
        return False, reason if reason else exc.__class__.__name__
    if not answer.startswith(b"HTTP/"):
        return False, "ответ не является HTTP"
    return True, ""


__all__ = [
    "apply",
    "probe_local",
    "rollback",
    "running",
    "snapshot",
    "stop",
]
