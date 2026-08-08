"""Compatibility UI forwards for the former WDTT creator menu."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _show_master_link(
    link: str,
    app: facade.ApplicationService,
    *,
    save: bool = True,
) -> None:
    """Keep the historic explicit secret renderer for external callers."""
    facade.panel(
        "qWDTT MASTER LINK",
        [
            "Ссылка содержит актуальные VK-хэши и общий пароль.",
            str(link),
        ],
        wrap=True,
    )
    if save:
        facade._save_link_to_file(str(link), "qwdtt_link.txt", app)


def setup_headless_creator(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    """Forward old entrypoints to the Calls-owned menu."""
    from hydra.ui.plugin_managers.calls import menu_calls

    menu_calls(state, app)


__all__ = ["_show_master_link", "setup_headless_creator"]
