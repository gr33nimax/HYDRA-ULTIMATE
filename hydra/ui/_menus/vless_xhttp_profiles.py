"""AnyTLS-style profile selector for VLESS/XHTTP."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.vless_xhttp import presets
from hydra.services.application import ApplicationService
from hydra.ui._menus.extended_protocol_common import (
    _application,
    _apply_error_text,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    NC,
    clear,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)


def open_menu(
    state: AppState,
    app: ApplicationService | None = None,
) -> None:
    """Select one coherent XHTTP transport profile."""
    app = _application(app)
    available = list(presets.PRESETS.values())

    while True:
        state = app.admin.load_state()
        current = app.plugin_query(
            "vless",
            "get_tuning",
            state=state,
        )
        current_name = (
            str(current.get("preset", "custom"))
            if isinstance(current, dict)
            else "custom"
        )
        current_label = presets.preset_label(current_name)
        clear()
        panel(
            "🌐 ПРОФИЛЬ ТРАНСПОРТА VLESS XHTTP",
            [
                f"Текущий профиль: {BOLD}{CYAN}{current_label}{NC}",
                "",
                "Профиль согласованно меняет режим, паддинг и буферы XHTTP.",
                "Клиенты получат параметры через новую ссылку или подписку.",
            ],
        )
        print()
        options = [
            (
                str(index),
                ("• " if item.name == current_name else "  ") + item.label,
                item.description,
            )
            for index, item in enumerate(available, start=1)
        ]
        options.append(("0", "↩ Назад", ""))
        choice = menu(options, "ПРОФИЛИ VLESS XHTTP")
        if choice == "0":
            return
        if not choice.isdigit():
            continue
        index = int(choice) - 1
        if not 0 <= index < len(available):
            continue
        selected = available[index]
        if selected.name == current_name:
            info("Этот профиль уже выбран")
        elif app.plugin_command(
            state,
            "vless",
            "set_preset",
            preset=selected.name,
        ):
            success(f"Профиль {selected.label} применён")
        else:
            error(
                _apply_error_text(
                    "Не удалось применить профиль XHTTP",
                    app,
                ),
            )
        prompt("Нажмите Enter")


__all__ = ["open_menu"]
