"""TUI adapter for advanced VLESS/XHTTP transport tuning."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.vless_xhttp import tuning
from hydra.services.application import ApplicationService
from hydra.ui.tui import error, menu, prompt, success


def _values(config: dict) -> dict[str, object]:
    """Return effective tuning values, tolerating an invalid stored config."""
    try:
        return tuning.effective(config)
    except ValueError:
        return {
            field.key: config.get(field.key, field.default)
            for field in tuning.FIELDS
        }


def _display(field: tuning.TuningField, value: object) -> str:
    if isinstance(field.default, bool):
        return "включено" if value else "выключено"
    if isinstance(field.default, dict):
        headers = value if isinstance(value, dict) else {}
        return (
            ", ".join(sorted(headers)) if headers else "не заданы"
        )
    return str(value)


def open_menu(
    state: AppState,
    app: ApplicationService,
) -> None:
    """Edit every XHTTP knob through transactional plugin commands."""
    while True:
        state = app.admin.load_state()
        desired = state.protocols.get("vless") or PluginState()
        values = _values(desired.config)
        items = [
            (
                str(index),
                field.label,
                f"{_display(field, values[field.key])} · {field.hint}",
            )
            for index, field in enumerate(tuning.FIELDS, start=1)
        ]
        choice = menu(
            [*items, ("0", "← Назад", "")],
            "ТОНКАЯ НАСТРОЙКА XHTTP",
        )
        if choice == "0":
            return
        try:
            index = int(choice) - 1
        except ValueError:
            continue
        if not 0 <= index < len(tuning.FIELDS):
            continue
        field = tuning.FIELDS[index]
        try:
            changed = _change(field, values[field.key], state, app)
            if changed is None:
                continue
            if changed:
                success(f"{field.label}: настройка обновлена")
            else:
                error("Не удалось применить настройки XHTTP")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _change(
    field: tuning.TuningField,
    current: object,
    state: AppState,
    app: ApplicationService,
) -> bool | None:
    if isinstance(field.default, dict):
        return _change_headers(current, state, app)
    if isinstance(field.default, bool):
        value: object = not current
    else:
        raw = prompt(f"{field.label} ({field.hint})", default=str(current))
        if not raw.strip():
            return None
        value = raw.strip()
    return app.plugin_command(
        state,
        "vless",
        "set_tuning",
        **{field.param: value},
    )


def _change_headers(
    current: object,
    state: AppState,
    app: ApplicationService,
) -> bool | None:
    headers = dict(current) if isinstance(current, dict) else {}
    action = menu(
        [
            ("1", "Добавить или изменить", "имя и значение заголовка"),
            ("2", "Удалить заголовок", "по имени"),
            ("3", "Очистить все", "вернуть пустой набор"),
            ("0", "Отмена", ""),
        ],
        "HTTP-ЗАГОЛОВКИ XHTTP",
    )
    if action == "1":
        name = prompt("Имя заголовка").strip()
        if not name:
            return None
        value = prompt("Значение заголовка", default=headers.get(name, ""))
        if not value.strip():
            return None
        headers[name] = value.strip()
    elif action == "2":
        name = prompt("Имя заголовка").strip()
        if not name:
            return None
        if name not in headers:
            raise ValueError(f"Заголовок {name} не задан")
        headers.pop(name)
    elif action == "3":
        headers = {}
    else:
        return None
    return app.plugin_command(
        state,
        "vless",
        "set_tuning",
        headers=headers,
    )


__all__ = ["open_menu"]
