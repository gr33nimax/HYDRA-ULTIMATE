"""Bounded local HTTPS checks for the subscription backend and SNI route."""
from __future__ import annotations

import json

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.services.admin import AdminCommandResult
from hydra.services.subscriptions.certificates import find_any_cert
from hydra.utils.commands import redact_text


def subscription_health(state: AppState, *, host: HostBackend) -> AdminCommandResult:
    certificate, key = find_any_cert(state)
    if not certificate or not key:
        return AdminCommandResult(False, "no_certificate")
    name = state.network.sub_domain or state.network.domain or state.network.server_ip
    if not name:
        return AdminCommandResult(False, "no_host")
    name = f"[{name}]" if ":" in name and not name.startswith("[") else name
    ports = (9443, 443) if state.network.sub_domain else (9443,)
    for port in ports:
        code = "backend_unavailable" if port == 9443 else "routing_unavailable"
        try:
            result = host.run([
                "curl", "--silent", "--show-error", "--fail", "--noproxy", "*",
                "--connect-timeout", "1", "--max-time", "3", "--proto", "=https",
                "--cacert", certificate, "--connect-to", f"{name}:{port}:127.0.0.1:{port}",
                f"https://{name}:{port}/healthz",
            ], timeout=4, text=True)
            if result.returncode != 0:
                detail = redact_text(str(result.stderr or "HTTPS request failed"))[:256]
                return AdminCommandResult(False, code, detail=detail)
            if json.loads(result.stdout) != {"status": "ok"}:
                return AdminCommandResult(False, code, detail="Unexpected health response")
        except Exception as exc:
            return AdminCommandResult(False, code, detail=redact_text(str(exc))[:256])
    return AdminCommandResult(True, "ready")
