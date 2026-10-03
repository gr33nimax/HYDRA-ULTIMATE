"""Pinned-management-only client material for technical connection probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.managed_node_models import ApplyReceipt, _identifier


_ALLOWED_OUTBOUND_KEYS = {
    "vless": {"type", "tag", "server", "server_port", "uuid", "flow", "tls", "transport", "packet_encoding", "multiplex"},
    "anytls": {"type", "tag", "server", "server_port", "password", "tls", "idle_session_check_interval", "idle_session_timeout", "min_idle_session"},
}
_ALLOWED_TLS_KEYS = {"enabled", "server_name", "alpn", "utls", "reality"}
_ALLOWED_TLS_NESTED = {"enabled", "fingerprint", "server_name", "public_key", "short_id", "alpn"}


@dataclass(frozen=True)
class ProbeMaterial:
    protocol: str
    client_config: dict[str, Any] = field(repr=False)

    def validate(self) -> None:
        _identifier(self.protocol, "probe.protocol")
        allowed = _ALLOWED_OUTBOUND_KEYS.get(self.protocol)
        if allowed is None:
            raise ValueError("probe protocol is not supported by the real client runner")
        if not isinstance(self.client_config, dict) or set(self.client_config) - allowed:
            raise ValueError("probe client material has unsupported fields")
        if self.client_config.get("type") != self.protocol:
            raise ValueError("probe client material has a different transport type")
        server = self.client_config.get("server")
        port = self.client_config.get("server_port")
        if not isinstance(server, str) or not server or len(server) > 253 or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("probe endpoint is invalid")
        secret_key = "uuid" if self.protocol == "vless" else "password"
        if not isinstance(self.client_config.get(secret_key), str) or not self.client_config[secret_key]:
            raise ValueError("probe technical credential is missing")
        tls = self.client_config.get("tls")
        if not isinstance(tls, dict) or set(tls) - _ALLOWED_TLS_KEYS or tls.get("enabled") is False:
            raise ValueError("probe TLS material has unsupported fields")
        _validate_json_tree(self.client_config, depth=0)

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {"protocol": self.protocol, "client_config": self.client_config}

    @classmethod
    def from_document(cls, raw: object) -> "ProbeMaterial":
        if not isinstance(raw, dict) or set(raw) != {"protocol", "client_config"}:
            raise ValueError("probe material has an invalid shape")
        item = cls(raw["protocol"], raw["client_config"])
        item.validate()
        return item


@dataclass(frozen=True)
class ProbeMaterials:
    node_id: str
    receipt: ApplyReceipt
    materials: list[ProbeMaterial]

    def validate(self) -> None:
        _identifier(self.node_id, "probe_materials.node_id")
        if not isinstance(self.receipt, ApplyReceipt):
            raise ValueError("probe material receipt is invalid")
        self.receipt.validate()
        if not isinstance(self.materials, list) or any(not isinstance(item, ProbeMaterial) for item in self.materials):
            raise ValueError("probe materials list is invalid")
        for item in self.materials:
            item.validate()
        protocols = [item.protocol for item in self.materials]
        if len(protocols) != len(set(protocols)):
            raise ValueError("probe materials contain duplicate protocols")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {"node_id": self.node_id, "receipt": self.receipt.to_document(), "materials": [item.to_document() for item in self.materials]}

    @classmethod
    def from_document(cls, raw: object) -> "ProbeMaterials":
        if not isinstance(raw, dict) or set(raw) != {"node_id", "receipt", "materials"} or not isinstance(raw["materials"], list):
            raise ValueError("probe materials response has an invalid shape")
        item = cls(raw["node_id"], ApplyReceipt.from_document(raw["receipt"]), [ProbeMaterial.from_document(value) for value in raw["materials"]])
        item.validate()
        return item


def _validate_json_tree(value: object, *, depth: int) -> None:
    if depth > 8:
        raise ValueError("probe client material is too deeply nested")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 64 or "private_key" in key.casefold() or "private-key" in key.casefold():
                raise ValueError("probe client material has an invalid key")
            if key == "tls" and isinstance(child, dict) and set(child) - _ALLOWED_TLS_KEYS:
                raise ValueError("probe TLS material has unsupported fields")
            if key in {"utls", "reality"} and isinstance(child, dict) and set(child) - _ALLOWED_TLS_NESTED:
                raise ValueError("probe TLS option has unsupported fields")
            _validate_json_tree(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 64:
            raise ValueError("probe client material list is too large")
        for child in value:
            _validate_json_tree(child, depth=depth + 1)
    elif value is not None and type(value) not in {str, int, float, bool}:
        raise ValueError("probe client material is not JSON data")


__all__ = ["ProbeMaterial", "ProbeMaterials"]
