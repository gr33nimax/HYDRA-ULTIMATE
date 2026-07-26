"""Context-scoped compatibility bridge for split manager implementations.

Legacy tests and integrations patch attributes on the public manager facade.
Implementations consume that facade through an explicitly bound proxy, keeping
the static import graph one-way: facade -> implementation -> bridge.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from types import ModuleType
from typing import Iterator


_CURRENT_FACADE: ContextVar[ModuleType | None] = ContextVar(
    "hydra_manager_facade",
    default=None,
)


class _FacadeProxy:
    def __getattr__(self, name: str):
        target = _CURRENT_FACADE.get()
        if target is None:
            raise RuntimeError(
                "manager implementation called without a bound facade",
            )
        return getattr(target, name)


facade = _FacadeProxy()


@contextmanager
def bind_facade(target: ModuleType) -> Iterator[None]:
    """Bind one stable manager facade for the duration of a UI operation."""
    token = _CURRENT_FACADE.set(target)
    try:
        yield
    finally:
        _CURRENT_FACADE.reset(token)


__all__ = ["bind_facade", "facade"]
