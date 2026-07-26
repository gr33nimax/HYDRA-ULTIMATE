"""NaiveProxy access-log parsing and authenticated traffic queries."""
from __future__ import annotations

import gzip
import json
import time
from collections.abc import Callable
from pathlib import Path

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .access_log_ingestion import (
    _access_log_paths as _access_log_paths,
    _non_negative_int as _non_negative_int,
    access_log_directions as _access_log_directions,
    ingest_access_logs as _ingest_access_logs,
)


def access_log_directions(data: dict) -> tuple[int, int]:
    """Return client Rx/Tx from a structured Caddy access-log record."""
    return _access_log_directions(data)


def ingest_access_logs(
    state: PluginStateAccess,
    log_dir: Path,
    derive_username: Callable[[User], str],
    cursors: dict,
    *,
    protocol: str = "naive",
) -> None:
    """Merge unread rotated access records using persisted inode cursors."""
    _ingest_access_logs(
        state,
        log_dir,
        derive_username,
        cursors,
        protocol=protocol,
        access_log_paths=_access_log_paths,
        directions=access_log_directions,
        normalize=_non_negative_int,
        json_loads=json.loads,
        gzip_open=gzip.open,
    )


class NaiveAccessLogMixin:
    """Serve traffic queries from Caddy's structured access logs."""

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        log_file = self._runtime_layout().log_dir / "access.log"
        if not self._installed() or not log_file.exists():
            return {}

        usernames = {
            self._derive_username(user): user.email
            for user in state.users
        }
        result: dict[str, int] = {}
        try:
            with log_file.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                for line in handle:
                    try:
                        data = json.loads(line)
                        username = data.get("user_id") or data.get("user")
                        email = usernames.get(username)
                        if email:
                            result[email] = (
                                result.get(email, 0)
                                + self._access_log_bytes(data)
                            )
                    except Exception:
                        continue
        except Exception:
            return result
        return result

    def ingest_traffic(
        self,
        state: PluginStateAccess,
        cursors: dict,
    ) -> None:
        ingest_access_logs(
            state,
            self._runtime_layout().log_dir,
            self._derive_username,
            cursors,
        )

    @staticmethod
    def _access_log_directions(data: dict) -> tuple[int, int]:
        return access_log_directions(data)

    @classmethod
    def _access_log_bytes(cls, data: dict) -> int:
        rx, tx = cls._access_log_directions(data)
        return rx + tx

    def recent_connections(
        self,
        state: PluginStateAccess,
        window_seconds: int = 300,
    ) -> list[dict]:
        """Return completed authenticated CONNECT requests in the window."""
        cutoff = time.time() - max(1, window_seconds)
        usernames = {
            self._derive_username(user): user.email
            for user in state.users
        }
        grouped: dict[str, dict] = {}
        for path in _access_log_paths(self._runtime_layout().log_dir):
            try:
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(
                    path,
                    "rt",
                    encoding="utf-8",
                    errors="replace",
                ) as handle:
                    self._collect_recent_records(
                        handle,
                        cutoff=cutoff,
                        usernames=usernames,
                        grouped=grouped,
                    )
            except OSError:
                continue
        return list(grouped.values())

    def _collect_recent_records(
        self,
        lines,
        *,
        cutoff: float,
        usernames: dict[str, str],
        grouped: dict[str, dict],
    ) -> None:
        for line in lines:
            try:
                data = json.loads(line)
                timestamp = float(data.get("ts", 0))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            if timestamp < cutoff:
                continue

            username = data.get("user_id") or data.get("user")
            email = usernames.get(username)
            if not email:
                continue
            request = data.get("request", {})
            method = (
                request.get("method", "")
                if isinstance(request, dict)
                else ""
            )
            if method and method != "CONNECT":
                continue

            rx, tx = self._access_log_directions(data)
            row = grouped.setdefault(
                email,
                {
                    "email": email,
                    "online": False,
                    "rx": 0,
                    "tx": 0,
                    "connections": 0,
                    "last_handshake": int(timestamp),
                    "activity_kind": "recent",
                },
            )
            row["rx"] += rx
            row["tx"] += tx
            row["connections"] += 1
            row["last_handshake"] = max(
                row["last_handshake"],
                int(timestamp),
            )
