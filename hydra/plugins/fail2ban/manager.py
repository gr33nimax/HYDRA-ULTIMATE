"""Compatibility alias for :mod:`hydra.ui.plugin_managers.fail2ban`."""
from __future__ import annotations

import sys

from hydra.core.state_models import get_protocol
from hydra.ui.plugin_managers import fail2ban as _implementation


def _effective_whitelist(state) -> list[str]:
    from hydra.plugins.fail2ban.plugin import Fail2banPlugin

    return Fail2banPlugin.effective_whitelist(state)


_menu_fail2ban = _implementation.menu_fail2ban


def _release_compatible_menu(state, app) -> None:
    """Expose automatic ``ignoreip`` entries through the decomposed UI."""
    from hydra.ui.plugin_managers import _fail2ban_menu as menu_impl
    from hydra.ui.plugin_managers import _fail2ban_whitelist as whitelist_impl

    original_options = menu_impl._options
    original_manage = whitelist_impl.manage
    original_panel = whitelist_impl.panel

    def options(state, installed, active, total_banned):
        result = original_options(state, installed, active, total_banned)
        if not installed:
            return result
        effective = _effective_whitelist(state)
        for index, (key, label, description) in enumerate(result):
            if key == "W":
                result[index] = (
                    key,
                    f"⚪ Управление whitelist "
                    f"{_implementation.DIM}({len(effective)} IP)"
                    f"{_implementation.NC}",
                    "Фактический ignoreip: ручные и автоматические адреса",
                )
                break
        return result

    def manage(state, app):
        def panel(title, lines):
            manual = get_protocol(
                state,
                "fail2ban",
            ).config.setdefault("whitelist", [])
            effective = _effective_whitelist(state)
            rendered = [
                f"  {_implementation.CYAN}{index:>2}."
                f"{_implementation.NC} {network} "
                f"{_implementation.DIM}(ручной){_implementation.NC}"
                for index, network in enumerate(manual, 1)
            ]
            rendered.extend(
                f"      {network} {_implementation.DIM}"
                f"(автоматический / из ignoreip){_implementation.NC}"
                for network in effective
                if network not in manual
            )
            return original_panel(
                "Фактический Fail2ban ignoreip",
                rendered if rendered else ["  Список пуст"],
            )

        whitelist_impl.panel = panel
        try:
            return original_manage(state, app)
        finally:
            whitelist_impl.panel = original_panel

    menu_impl._options = options
    menu_impl.manage_whitelist = manage
    try:
        _menu_fail2ban(state, app)
    finally:
        menu_impl._options = original_options
        menu_impl.manage_whitelist = original_manage


_implementation.menu_fail2ban = _release_compatible_menu
sys.modules[__name__] = _implementation
