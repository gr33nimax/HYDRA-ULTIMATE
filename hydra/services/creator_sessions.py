"""Provider-neutral creation and lifecycle of room creator sessions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping, Protocol


CreatorLifetime = Literal["transient", "managed"]


@dataclass(frozen=True)
class CreatorSessionRequest:
    """Describe sessions requested by one application consumer."""

    provider: str
    consumer: str
    lifetime: CreatorLifetime
    count: int = 1
    previous_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class CreatorEndpoint:
    """Provider result with a public URI and its opaque endpoint token."""

    uri: str
    token: str


@dataclass(frozen=True)
class CreatorSessionGroup:
    """Typed handle returned by a provider for one consumer request."""

    request: CreatorSessionRequest
    endpoints: tuple[CreatorEndpoint, ...]
    handle: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class CreatorProviderAvailability:
    installed: bool
    credentials_ready: bool


class CreatorProviderDriver(Protocol):
    """Provider-specific runtime hidden behind the shared session layer."""

    def create_sessions(
        self,
        request: CreatorSessionRequest,
    ) -> CreatorSessionGroup: ...

    def creator_availability(self) -> CreatorProviderAvailability: ...
    def commit_sessions(self, group: CreatorSessionGroup) -> None: ...
    def finalize_sessions(self, group: CreatorSessionGroup) -> None: ...
    def rollback_sessions(self, group: CreatorSessionGroup) -> None: ...
    def close_sessions(self, group: CreatorSessionGroup) -> None: ...
    def stop_managed_sessions(self, consumer: str) -> tuple[bool, str]: ...


class CreatorSessions(Protocol):
    def availability(self, provider: str) -> CreatorProviderAvailability: ...
    def create(self, request: CreatorSessionRequest) -> CreatorSessionGroup: ...
    def commit(self, group: CreatorSessionGroup) -> None: ...
    def finalize(self, group: CreatorSessionGroup) -> None: ...
    def rollback(self, group: CreatorSessionGroup) -> None: ...
    def close(self, group: CreatorSessionGroup) -> None: ...
    def stop_managed(self, provider: str, consumer: str) -> tuple[bool, str]: ...


@dataclass(frozen=True)
class CreatorSessionManager:
    """Dispatch requests without knowing Calls, qWDTT or provider details."""

    providers: Mapping[str, CreatorProviderDriver]

    def availability(self, provider: str) -> CreatorProviderAvailability:
        return self._driver(provider).creator_availability()

    def create(self, request: CreatorSessionRequest) -> CreatorSessionGroup:
        driver = self._driver(request.provider)
        self._validate_request(request)
        group = driver.create_sessions(request)
        if group.request != request or len(group.endpoints) != request.count:
            try:
                driver.rollback_sessions(group)
            finally:
                raise RuntimeError("creator provider returned an invalid session group")
        if any(not endpoint.token for endpoint in group.endpoints):
            try:
                driver.rollback_sessions(group)
            finally:
                raise RuntimeError("creator provider returned an empty endpoint token")
        return group

    def commit(self, group: CreatorSessionGroup) -> None:
        self._driver(group.request.provider).commit_sessions(group)

    def finalize(self, group: CreatorSessionGroup) -> None:
        self._driver(group.request.provider).finalize_sessions(group)

    def rollback(self, group: CreatorSessionGroup) -> None:
        self._driver(group.request.provider).rollback_sessions(group)

    def close(self, group: CreatorSessionGroup) -> None:
        self._driver(group.request.provider).close_sessions(group)

    def stop_managed(self, provider: str, consumer: str) -> tuple[bool, str]:
        normalized = self._name(consumer, "consumer")
        return self._driver(provider).stop_managed_sessions(normalized)

    def _driver(self, provider: str) -> CreatorProviderDriver:
        name = self._name(provider, "provider")
        try:
            return self.providers[name]
        except KeyError as exc:
            raise ValueError(f"unknown creator provider: {name}") from exc

    @classmethod
    def _validate_request(cls, request: CreatorSessionRequest) -> None:
        cls._name(request.consumer, "consumer")
        if request.lifetime not in ("transient", "managed"):
            raise ValueError("creator lifetime must be transient or managed")
        if type(request.count) is not int or request.count < 1:
            raise ValueError("creator session count must be a positive integer")
        if request.lifetime == "transient" and request.count != 1:
            raise ValueError("transient creator requests must contain one session")
        if len(set(request.previous_tokens)) != len(request.previous_tokens):
            raise ValueError("previous creator endpoint tokens must be unique")

    @staticmethod
    def _name(value: str, field_name: str) -> str:
        normalized = str(value or "").strip().lower()
        if not normalized or not normalized.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"creator {field_name} has an invalid name")
        return normalized


__all__ = [
    "CreatorEndpoint",
    "CreatorLifetime",
    "CreatorProviderAvailability",
    "CreatorProviderDriver",
    "CreatorSessionGroup",
    "CreatorSessionManager",
    "CreatorSessionRequest",
    "CreatorSessions",
]
