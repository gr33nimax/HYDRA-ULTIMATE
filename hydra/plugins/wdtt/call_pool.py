"""qWDTT projection of VK call hashes owned by the Calls service."""
from __future__ import annotations

from urllib.parse import quote

from hydra.core.state_creator_models import (
    MAX_QWDTT_ROOM_COUNT,
    MIN_QWDTT_ROOM_COUNT,
)
from hydra.plugins.context import PluginStateAccess


def normalize_qwdtt_hashes(
    hashes: list[str],
    *,
    expected_count: int | None = None,
) -> list[str]:
    """Validate the comma-separated hash field without changing token order."""
    if not isinstance(hashes, list):
        raise ValueError("qWDTT hashes must be a list")
    clean_hashes: list[str] = []
    for item in hashes:
        if not isinstance(item, str):
            raise ValueError("qWDTT hashes must be strings")
        token = item.strip()
        if not token or "," in token or any(char.isspace() for char in token):
            raise ValueError("qWDTT hashes must be non-empty comma-free tokens")
        clean_hashes.append(token)
    if len(set(clean_hashes)) != len(clean_hashes):
        raise ValueError("qWDTT hashes must be unique")
    if expected_count is not None and len(clean_hashes) != expected_count:
        raise ValueError(f"exactly {expected_count} unique VK call hashes are required")
    if not MIN_QWDTT_ROOM_COUNT <= len(clean_hashes) <= MAX_QWDTT_ROOM_COUNT:
        raise ValueError(
            f"between {MIN_QWDTT_ROOM_COUNT} and {MAX_QWDTT_ROOM_COUNT} "
            "VK call hashes are required",
        )
    return clean_hashes


def build_qwdtt_link(
    server_ip: str,
    dtls_port: int,
    password: str,
    hashes: list[str],
    *,
    workers: int = 16,
    local_port: int = 9000,
) -> str:
    clean_hashes = normalize_qwdtt_hashes(hashes)
    name = quote(f"qWDTT-{server_ip}", safe="-._~")
    peer_host = f"[{server_ip}]" if ":" in server_ip and not server_ip.startswith("[") else server_ip
    peer = quote(f"{peer_host}:{int(dtls_port)}", safe=":[]-._~")
    encoded_hashes = ",".join(
        quote(token, safe="-._~")
        for token in clean_hashes
    )
    encoded_password = quote(str(password), safe="-._~")
    return (
        f"qwdtt://config?name={name}&peer={peer}&hashes={encoded_hashes}"
        f"&workers={int(workers)}&port={int(local_port)}&pass={encoded_password}"
    )


class WdttCallPoolMixin:
    """Publish only the WDTT-specific artifact, never manage VK rooms."""

    def update_call_pool_artifact(
        self,
        *,
        state: PluginStateAccess | None = None,
        hashes: list[str] | None = None,
        restore_link: str | None = None,
    ) -> dict[str, object]:
        env = self._wdtt_env()
        previous = self.qwdtt_call_pool_link()
        if restore_link is not None:
            normalized = str(restore_link).strip()
            if normalized and not normalized.startswith("qwdtt://config?"):
                raise ValueError("invalid qWDTT rollback link")
            if normalized:
                env.host.atomic_write(
                    env.headless_link_file,
                    normalized + "\n",
                    mode=0o600,
                )
            else:
                env.host.remove_file(env.headless_link_file, missing_ok=True)
            return {"ok": True, "previous_link": previous}
        if state is None or hashes is None:
            raise ValueError("state and VK call hashes are required")
        desired = state.protocols.get("wdtt")
        if desired is None or not desired.enabled:
            raise ValueError("qWDTT is disabled")
        try:
            data = env.json_module.loads(
                env.passwords_file.read_text(encoding="utf-8"),
            )
            password = str(data.get("main_password", ""))
        except Exception:
            password = ""
        password = password or str(
            desired.config.get("main_password", env.system_password),
        )
        server_ip = str(state.network.server_ip or env.public_ip())
        dtls_port = int(
            desired.config.get("dtls_port", env.default_dtls_port),
        )
        link = build_qwdtt_link(
            server_ip,
            dtls_port,
            password,
            hashes,
            local_port=env.local_tun_port,
        )
        env.host.atomic_write(env.headless_link_file, link + "\n", mode=0o600)
        return {"ok": True, "previous_link": previous}

    def clear_call_pool_artifact(self) -> dict[str, object]:
        env = self._wdtt_env()
        previous = self.qwdtt_call_pool_link()
        env.host.remove_file(
            env.headless_link_file,
            missing_ok=True,
        )
        return {"ok": True, "previous_link": previous}

    def qwdtt_call_pool_link(self) -> str:
        path = self._wdtt_env().headless_link_file
        try:
            return path.read_text(encoding="utf-8").strip() if path.exists() else ""
        except OSError:
            return ""

    def manual_client_artifacts(
        self,
        *,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        del state
        link = self.qwdtt_call_pool_link()
        if not link:
            return []
        return [{
            "profile_name": "master",
            "profile_label": "Master · общая для всех пользователей",
            "links": [link],
        }]


__all__ = ["WdttCallPoolMixin", "build_qwdtt_link", "normalize_qwdtt_hashes"]
