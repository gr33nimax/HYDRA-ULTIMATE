"""The AmneziaWG generation switch, kept out of the facade that draws the menu."""

from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import confirm, error, menu, prompt, success

from hydra.ui._menus.extended_protocol_common import _apply_error_text


def _awg_switch_version(state: AppState, p, app: ApplicationService) -> None:
    """Ask for a generation and switch the server to it.

    The command answers False for two very different things: "the generation is already what was
    asked for" and "the apply was refused and the state was rolled back". Reporting both as "this
    version is already active" is what hid a real refusal from the operator, so the stored
    generation is read before the call to tell the two apart.
    """
    target = menu(
        [
            ("1", "AWG 2.0", "Максимальная совместимость"),
            ("2", "AWG 3.0", "Нужны совместимые клиенты"),
            ("3", "AWG 3.1", "Нужны совместимые клиенты"),
        ],
        "ВЕРСИЯ AMNEZIAWG",
    )
    selected = {"1": "2.0", "2": "3.0", "3": "3.1"}.get(target)
    if not selected or not confirm(f"Переключить сервер на AWG {selected}?", default=False):
        return

    protocol = state.protocols.get("amneziawg")
    before = str((protocol.config.get("protocol_mode") if protocol else None) or "2.0")
    try:
        changed = app.plugin_command(state, "amneziawg", "set_protocol_mode", mode=selected)
        if changed:
            success("Версия AWG применена")
        elif before == selected:
            success("Эта версия уже активна")
        else:
            error(f"Не применено: {_apply_error_text(app=app)}")
    except (RuntimeError, ValueError, OSError) as exc:
        error(f"Не удалось переключить AWG: {exc}")
    prompt("Нажмите Enter")
