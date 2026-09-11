"""Configuration-name editors shared by global and per-user menus."""
from __future__ import annotations

from hydra.core.state_models import AppState, User
from hydra.services.application import ApplicationService
from hydra.ui._menus.users_links import (
    _artifact_name_key,
    _artifact_title,
    _client_artifacts,
)
from hydra.ui.tui import error, menu, prompt, success, warn


def edit_configuration_name(
    state: AppState,
    user: User,
    app: ApplicationService,
    *,
    global_scope: bool = False,
) -> None:
    artifacts = _client_artifacts(state, user, app)
    if not artifacts:
        warn("Нет доступных конфигураций.")
        prompt("Нажмите Enter")
        return
    names = (
        state.configuration_names
        if global_scope
        else user.configuration_name_overrides
    )
    choices = []
    for index, artifact in enumerate(artifacts, start=1):
        key = _artifact_name_key(artifact)
        default = _artifact_title(artifact)
        current = names.get(key)
        choices.append((
            str(index),
            f"{default} → {current}" if current else default,
            "",
        ))
    choices.append(("0", "↩ Назад", ""))
    selected = menu(choices, "НАЗВАНИЕ КОНФИГУРАЦИИ")
    if selected == "0":
        return
    try:
        artifact = artifacts[int(selected) - 1]
    except (ValueError, IndexError):
        return
    key = _artifact_name_key(artifact)
    label = "Общее название" if global_scope else "Личное название"
    value = prompt(
        f"{label} (пусто — вернуть стандартное)",
        default=names.get(key, ""),
    )
    try:
        if global_scope:
            app.configuration_names.set_global(state, key, value)
        else:
            app.configuration_names.set_user(state, user.email, key, value)
        app.admin.save_state(state)
        success("Название конфигурации сохранено.")
    except ValueError as exc:
        error(str(exc))
    prompt("Нажмите Enter")


def edit_global_configuration_names(
    state: AppState,
    app: ApplicationService,
) -> None:
    user = next((item for item in state.users if not item.blocked), None)
    if user is None and state.users:
        user = state.users[0]
    if user is None:
        warn("Сначала добавьте пользователя, чтобы получить список конфигураций.")
        prompt("Нажмите Enter")
        return
    edit_configuration_name(state, user, app, global_scope=True)


__all__ = ["edit_configuration_name", "edit_global_configuration_names"]
