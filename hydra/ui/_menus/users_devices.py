"""Device view and limit control for one user."""
from __future__ import annotations

from datetime import datetime, timezone

from hydra.core.state_models import AppState, User
from hydra.services.application import ApplicationService
from hydra.services.device_sessions import user_sessions
from hydra.ui._menus.device_formatting import address_label, source_label
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    confirm,
    error,
    menu,
    panel,
    prompt,
    success,
)


def _ago(moment: float) -> str:
    """Render how long ago something happened, in words."""
    if moment <= 0:
        return "—"
    seconds = max(0, int(datetime.now(timezone.utc).timestamp() - moment))
    if seconds < 60:
        return "только что"
    if seconds < 3600:
        return f"{seconds // 60} мин. назад"
    if seconds < 86400:
        return f"{seconds // 3600} ч. назад"
    days = seconds // 86400
    return f"{days} дн. назад" if days < 100 else "давно"


def _timestamp(value: str) -> str:
    """Render a stored ISO timestamp compactly, leaving junk untouched."""
    try:
        return datetime.fromisoformat(value).strftime("%d.%m %H:%M")
    except (TypeError, ValueError):
        return value[:16] if value else "—"


def device_lines(state: AppState, user: User) -> list[str]:
    """Build the device report shown in the user's device screen."""
    limit = user.device_limit
    lines = [
        f"  {DIM}Лимит:{NC} "
        + (
            f"{BOLD}{limit}{NC} одновременно подключённых устройств"
            if limit
            else f"{BOLD}без ограничения{NC}"
        ),
        "",
        f"{BOLD}{WHITE}Зарегистрированные (по запросам подписки):{NC}",
    ]
    if not user.devices:
        lines.append(f"  {DIM}подписку ещё не запрашивали{NC}")
    for device_id, record in sorted(
        user.devices.items(),
        key=lambda item: str(item[1].get("last_seen", "")),
        reverse=True,
    ):
        client = str(record.get("user_agent", "")).strip() or "клиент не назвался"
        lines.append(
            f"  {CYAN}{device_id[:12]}{NC}  {client[:24]:<24} "
            f"{_timestamp(str(record.get('last_seen', '')))}",
        )
        lines.append(
            f"  {DIM}    {source_label(str(record.get('source', '')), client)[:22]} · "
            f"{address_label(str(record.get('address', '')))} · с "
            f"{_timestamp(str(record.get('first_seen', '')))}{NC}",
        )

    sessions = user_sessions(state, user.email)
    lines.extend(["", f"{BOLD}{WHITE}Подключены сейчас:{NC}"])
    if not sessions:
        lines.append(f"  {DIM}активных подключений нет{NC}")
    for session in sessions:
        marker = f"{GREEN}●{NC}" if session.connections else f"{DIM}○{NC}"
        state_text = (
            f"{RED}сверх лимита{NC}"
            if not session.allowed
            else f"{session.connections} соед."
        )
        lines.append(
            f"  {marker} {address_label(session.address)[:24]:<24} {state_text:<18} "
            f"{_bytes_auto(session.bytes_total):>9}  {_ago(session.last_seen)}",
        )
    if any(not session.allowed for session in sessions):
        lines.extend(
            [
                "",
                f"  {YELLOW}Подключения сверх лимита закрываются автоматически;{NC}",
                f"  {YELLOW}первыми остаются устройства, подключившиеся раньше.{NC}",
            ],
        )
    return lines


def open_menu(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> None:
    """Show what connected and let the operator change the device limit."""
    while True:
        clear()
        panel(f"📱  УСТРОЙСТВА: {user.email}", device_lines(state, user))
        print()
        choice = menu(
            [
                ("1", "Изменить лимит", "Сколько устройств может быть онлайн"),
                ("2", "Сбросить привязки", "Забыть зарегистрированные устройства"),
                ("0", "↩ Назад", ""),
            ],
            f"УСТРОЙСТВА {user.email}",
        )
        if choice == "0":
            return
        if choice == "1":
            _change_limit(state, user, app)
        elif choice == "2":
            _reset_devices(state, user, app)


def _change_limit(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> None:
    raw_limit = prompt(
        "Максимум одновременных устройств (0 = без ограничений)",
        default=str(user.device_limit),
    )
    try:
        limit = int(raw_limit)
        if limit < 0:
            raise ValueError
    except ValueError:
        error("Лимит должен быть целым неотрицательным числом.")
        prompt("Нажмите Enter")
        return
    app.set_user_device_limit(state, user.email, limit, reset=False)
    user.device_limit = limit
    success(
        "Лимит устройств: "
        + (str(limit) if limit else "без ограничений"),
    )
    prompt("Нажмите Enter")


def _reset_devices(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> None:
    if not confirm("Сбросить зарегистрированные устройства?", default=False):
        return
    app.set_user_device_limit(
        state,
        user.email,
        user.device_limit,
        reset=True,
    )
    user.devices.clear()
    success("Привязки сброшены; следующие запросы подписки создадут их заново")
    prompt("Нажмите Enter")


__all__ = ["device_lines", "open_menu"]
