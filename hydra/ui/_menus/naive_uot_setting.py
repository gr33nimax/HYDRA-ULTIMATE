"""The UoT switch of the NaiveProxy settings screen."""

from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.tui import confirm, error, prompt


UOT_OPTION = "UDP через TCP (UoT)"


def uot_desired(state: AppState) -> bool:
    """The stored UoT mode; an absent value means enabled."""
    protocol = state.protocols.get("naive", PluginState())
    return bool(protocol.config.get("uot", True))


def uot_option_value(state: AppState) -> str:
    return "Включено" if uot_desired(state) else "Выключено"


def change_uot(
    state: AppState,
    app: ApplicationService,
) -> bool | None:
    """Flip UoT; returns None when the operator cancelled the warning."""
    enabled = uot_desired(state)
    if enabled and not confirm(
        "Выключить UoT? Caddy будет пересобран без него, и UDP по TCP-профилю перестанет ходить.",
        default=False,
    ):
        return None
    try:
        changed = app.plugin_command(state, "naive", "set_uot", uot=not enabled)
    except ValueError as exc:
        error(str(exc))
        prompt("Нажмите Enter")
        return None
    prompt("Нажмите Enter")
    return changed
