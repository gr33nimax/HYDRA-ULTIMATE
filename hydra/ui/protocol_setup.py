"""Compatibility facade for protocol-specific interactive setup widgets."""
from __future__ import annotations

from collections.abc import Callable

from hydra.ui.tui import menu, prompt


def choose_shadowtls_sni(
    *,
    choose: Callable[..., str] = menu,
    ask: Callable[..., str] = prompt,
) -> str:
    from hydra.ui._menus.shadowtls_settings import (
        choose_shadowtls_sni as choose_value,
    )

    return choose_value(choose=choose, ask=ask)


__all__ = ["choose_shadowtls_sni"]
