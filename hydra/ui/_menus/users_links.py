"""Subscription links and contract-driven client artifact views."""
from __future__ import annotations

from dataclasses import dataclass

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.subscriptions.generator import get_subscription_urls
from hydra.services.user_access import access_status as get_user_access_status
from hydra.ui._menus.users_common import _application
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    clear,
    kv,
    panel,
    prompt,
    title,
    warn,
)


@dataclass(frozen=True)
class _ClientArtifact:
    plugin_name: str
    display_name: str
    profile_name: str
    profile_label: str
    config: str
    links: tuple[str, ...]


def _profile_specs(
    state: AppState,
    plugin_name: str,
    app: ApplicationService,
) -> list[tuple[str, str]]:
    try:
        profiles = app.protocols.client_profiles(state, plugin_name)
    except Exception:
        profiles = []
    result = [
        (
            str(profile.get("name", "")).strip(),
            str(
                profile.get("label")
                or profile.get("name")
                or "",
            ).strip(),
        )
        for profile in profiles
        if isinstance(profile, dict) and profile.get("name")
    ]
    return result or [("", "")]


def _client_artifacts(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> list[_ClientArtifact]:
    artifacts: list[_ClientArtifact] = []
    plugin_names = app.protocols.enabled_subscription_names(
        state,
        PluginCategory.TRANSPORT,
    )
    for plugin_name in sorted(plugin_names):
        for profile_name, profile_label in _profile_specs(
            state,
            plugin_name,
            app,
        ):
            parameters = (
                {"profile": profile_name}
                if profile_name
                else {}
            )
            try:
                config = (
                    app.protocols.client_config(
                        state,
                        plugin_name,
                        user,
                        **parameters,
                    )
                    or ""
                )
            except Exception:
                config = ""
            try:
                links = tuple(
                    dict.fromkeys(
                        link
                        for link in app.protocols.client_links(
                            state,
                            plugin_name,
                            user,
                            **parameters,
                        )
                        if link
                    ),
                )
            except Exception:
                links = ()
            if config or links:
                artifacts.append(
                    _ClientArtifact(
                        plugin_name,
                        app.protocols.display_name(plugin_name),
                        profile_name,
                        profile_label,
                        config,
                        links,
                    ),
                )
    return artifacts


def _artifact_title(artifact: _ClientArtifact) -> str:
    label = protocol_label(
        artifact.plugin_name,
        artifact.display_name,
    )
    if artifact.profile_label:
        return f"{label} ({artifact.profile_label})"
    return label


def _render_qr(value: str, *, invert: bool = False) -> None:
    if not value:
        return
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(value)
        qr.print_ascii(invert=invert)
    except Exception:
        pass


def _link_caption(link: str) -> str:
    if link.startswith("vpn://"):
        return "Импорт в AmneziaVPN"
    if link.startswith("wg://"):
        return "WireGuard URL"
    return "Ссылка"


def _render_inline_artifact(artifact: _ClientArtifact) -> None:
    heading = _artifact_title(artifact)
    fill = max(0, PANEL_W - 10 - len(heading))
    print(
        f"  {CYAN}── {BOLD}{heading}{NC}"
        f"{CYAN}{'─' * fill}{NC}",
    )
    for link in artifact.links:
        print(f"  {GREEN}{_link_caption(link)}:{NC}")
        print(link)
    if artifact.config:
        _render_qr(artifact.config)
        print(f"  {DIM}{'─' * PANEL_W}{NC}")
        for line in artifact.config.splitlines():
            print(line)
        print(f"  {DIM}{'─' * PANEL_W}{NC}")
    print()


def _user_links(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
) -> None:
    """Show every per-user client artifact through the plugin contract."""
    app = _application(app)
    clear()
    print(
        f"\n  {CYAN}Конфиги и ссылки для {BOLD}{user.email}{NC}\n",
    )
    artifacts = _client_artifacts(state, user, app)
    if not artifacts:
        warn("Нет доступных клиентских конфигураций.")
    for artifact in artifacts:
        _render_inline_artifact(artifact)
    prompt("Нажмите Enter")


def _show_subscription_links(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
) -> None:
    """Show canonical subscription endpoints separately from raw artifacts."""
    app = _application(app)
    clear()
    title(f"Подписка: {user.email}")
    if not app.admin.unit_active("hydra-sub"):
        warn(
            "Сервер подписок не запущен. Включите его в меню "
            "«Сервер подписок», затем повторите попытку.",
        )
        prompt("Нажмите Enter")
        return
    cert_file, key_file = app.admin.subscription_certificate(state)
    if not cert_file or not key_file:
        warn(
            "Сервер подписок не готов: HTTPS-сертификат отсутствует.",
        )
        prompt("Нажмите Enter")
        return
    urls = get_subscription_urls(user, state)
    available, reason = get_user_access_status(user)
    panel(
        "ДОСТУП",
        [
            kv("Статус:", f"{GREEN if available else RED}{reason}{NC}"),
            kv("Обновление:", "каждые 6 часов"),
        ],
    )
    print()
    print(f"  {BOLD}Основная ссылка (рекомендуется){NC}")
    print(
        f"  {DIM}NekoBox, Shadowrocket и Throne определяются "
        f"автоматически по приложению.{NC}",
    )
    print(urls["auto"])
    print()
    print(f"  {BOLD}Ручной выбор формата{NC}")
    for label, key in (
        ("NekoBox", "nekobox"),
        ("Shadowrocket", "shadowrocket"),
        ("Throne", "throne"),
        ("Sing-Box JSON", "singbox"),
    ):
        print(f"  {label}:")
        print(urls[key])
    print(
        f"\n  {DIM}Ссылка содержит секретный токен — "
        f"передавайте её только владельцу.{NC}",
    )
    prompt("Нажмите Enter")


def _user_configs(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
) -> None:
    """Render profiles and formats without protocol-name branches."""
    app = _application(app)
    clear()
    title(f"Конфигурации для пользователя: {user.email}")
    artifacts = _client_artifacts(state, user, app)
    if not artifacts:
        warn("Нет включённых протоколов с клиентскими конфигурациями.")
        prompt("Нажмите Enter")
        return
    for artifact in artifacts:
        _render_inline_artifact(artifact)
        if artifact.config:
            _render_qr(artifact.config, invert=True)
    print()
    prompt("Нажмите Enter")
