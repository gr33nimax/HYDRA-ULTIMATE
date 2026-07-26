"""TUI adapter for VLESS/XHTTP desired settings."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.vless_xhttp import presets, tuning
from hydra.plugins.vless_xhttp.security import (
    DEFAULT_HANDSHAKE,
    MODE_REALITY,
    MODE_TLS,
    handshake_target,
    is_reality,
    security_mode,
)
from hydra.services.application import ApplicationService
from hydra.ui._menus.decoy_theme import open_decoy_menu, theme_label
from hydra.ui._menus.vless_xhttp_tuning import open_menu as open_tuning_menu
from hydra.ui.tui import error, menu, prompt, success


_MODE_HINTS = {
    "stream-up": "загрузка одним потоком, скачивание отдельными запросами",
    "packet-up": "загрузка отдельными POST, устойчиво к посредникам",
    "stream-one": "один поток в обе стороны, минимальная задержка",
}


def option(_desired: PluginState) -> tuple[str, str]:
    return "⚙️  Настройки", "TLS-режим, домен, путь, XHTTP, uTLS и заглушка"


def _security_row(config: dict) -> tuple[str, str]:
    """Describe how the endpoint obtains its TLS handshake."""
    try:
        if is_reality(config):
            return (
                "reality",
                f"чужое рукопожатие {handshake_target(config)}, сертификат не нужен",
            )
        return (
            "tls",
            "свой сертификат на домене, TLS завершает Caddy",
        )
    except ValueError as exc:
        return "invalid", str(exc)


def _summary(config: dict) -> tuple[str, str]:
    """Return the preset label and tuning summary of a desired config."""
    try:
        return (
            presets.preset_label(presets.current_preset(config)),
            tuning.summary(config),
        )
    except ValueError as exc:
        return "🛠 Пользовательский", str(exc)


def open_menu(
    state: AppState,
    plugin: object,
    app: ApplicationService,
) -> None:
    while True:
        state = app.admin.load_state()
        desired = state.protocols.get("vless") or PluginState()
        domain = str(desired.config.get("domain", ""))
        path = str(desired.config.get("xhttp_path", "/xhttp"))
        mode = str(desired.config.get("xhttp_mode", "stream-up"))
        _preset_label, tuning_summary = _summary(desired.config)
        fingerprint = str(desired.config.get("utls_fingerprint", "none"))
        decoy = str(desired.config.get("decoy_theme", "media"))
        mode_name, mode_hint = _security_row(desired.config)
        reality = mode_name == MODE_REALITY
        choice = menu(
            [
                ("1", "TLS-режим", f"{mode_name} — {mode_hint}"),
                (
                    "2",
                    "Домен" if not reality else "Домен (не используется)",
                    domain or "не настроен",
                ),
                (
                    "3",
                    "Путь XHTTP",
                    f"{path} — "
                    + (
                        "путь внутри чужого имени"
                        if reality
                        else "этот путь Caddy отдаёт в Sing-Box"
                    ),
                ),
                ("4", "Режим XHTTP", f"{mode} — {_MODE_HINTS.get(mode, '')}"),
                ("5", "Тонкая настройка", tuning_summary),
                (
                    "6",
                    "uTLS-отпечаток клиента",
                    fingerprint
                    if fingerprint != "none"
                    else (
                        "none — в Reality клиент получит chrome"
                        if reality
                        else "none — клиент решает сам"
                    ),
                ),
                (
                    "7",
                    "Сайт-заглушка",
                    f"{theme_label(decoy)} — остальные URL домена"
                    if not reality
                    else "не используется в режиме reality",
                ),
                ("0", "← Назад", ""),
            ],
            "НАСТРОЙКИ VLESS + XHTTP",
        )
        if choice == "0":
            return
        try:
            changed = _change(choice, state, desired, plugin, app)
            if changed is None:
                continue
            if changed:
                success("Настройки VLESS + XHTTP обновлены")
            else:
                error("Не удалось применить настройки VLESS + XHTTP")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _change(
    choice: str,
    state: AppState,
    desired: PluginState,
    plugin: object,
    app: ApplicationService,
) -> bool | None:
    if choice == "1":
        return _change_security(state, desired, app)
    if choice == "2":
        value = prompt(
            "Новый домен VLESS + XHTTP",
            default=str(desired.config.get("domain", "")),
        )
        if not value:
            return None
        return app.plugin_command(
            state,
            "vless",
            "set_domain",
            domain=value,
        )
    if choice == "3":
        value = prompt(
            "Новый XHTTP path",
            default=str(desired.config.get("xhttp_path", "/xhttp")),
        )
        return app.plugin_command(
            state,
            "vless",
            "set_path",
            path=value,
        )
    if choice == "4":
        selected = menu(
            [
                ("1", "stream-up", _MODE_HINTS["stream-up"]),
                ("2", "packet-up", _MODE_HINTS["packet-up"]),
                ("3", "stream-one", _MODE_HINTS["stream-one"]),
                ("0", "Отмена", ""),
            ],
            "РЕЖИМ XHTTP",
        )
        mode = {
            "1": "stream-up",
            "2": "packet-up",
            "3": "stream-one",
        }.get(selected)
        if mode is None:
            return None
        return app.plugin_command(
            state,
            "vless",
            "set_mode",
            mode=mode,
        )
    if choice == "5":
        open_tuning_menu(state, app)
        return None
    if choice == "6":
        return _change_fingerprint(state, desired, app)
    if choice == "7":
        open_decoy_menu(state, plugin, app)
        return None
    return None


def _change_security(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> bool | None:
    """Switch between an own certificate and a borrowed Reality handshake."""
    current = security_mode(desired.config)
    selected = menu(
        [
            (
                "1",
                "tls — свой сертификат" + (" ·" if current == MODE_TLS else ""),
                "Нужен домен с A-записью на сервер; TLS завершает Caddy, "
                "остальные URL отдаёт заглушка",
            ),
            (
                "2",
                "reality — чужое рукопожатие"
                + (" ·" if current == MODE_REALITY else ""),
                "Домен и сертификат не нужны; сервер повторяет TLS чужого "
                "сайта, клиенты подключаются по IP",
            ),
            ("0", "Отмена", ""),
        ],
        "TLS-РЕЖИМ VLESS",
    )
    if selected == "1":
        return app.plugin_command(state, "vless", "set_security", mode=MODE_TLS)
    if selected != "2":
        return None
    handshake = prompt(
        "Чужой хост для рукопожатия (TLS 1.3, HTTP/2, не из РФ)",
        default=str(
            desired.config.get("reality_handshake") or DEFAULT_HANDSHAKE,
        ),
    ).strip()
    if not handshake:
        return None
    return app.plugin_command(
        state,
        "vless",
        "set_security",
        mode=MODE_REALITY,
        handshake=handshake,
    )


def _change_fingerprint(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> bool | None:
    from hydra.plugins.vless_xhttp.tuning import UTLS_FINGERPRINTS

    current = str(desired.config.get("utls_fingerprint", "none"))
    options = [
        (
            str(index),
            name + (" ·" if name == current else ""),
            "как у браузера" if name not in {"random", "randomized"} else "случайный",
        )
        for index, name in enumerate(UTLS_FINGERPRINTS, start=1)
    ]
    selected = menu(
        [*options, ("0", "Отмена", "")],
        "uTLS-ОТПЕЧАТОК КЛИЕНТА",
    )
    if not selected.isdigit() or selected == "0":
        return None
    index = int(selected) - 1
    if not 0 <= index < len(UTLS_FINGERPRINTS):
        return None
    return app.plugin_command(
        state,
        "vless",
        "set_tuning",
        utls_fingerprint=UTLS_FINGERPRINTS[index],
    )


__all__ = ["open_menu", "option"]
