"""Меню протокола «VLESS через CDN»: установка, профиль клиента, страница."""

from __future__ import annotations

from datetime import datetime, timezone

from hydra.contracts.vless_cdn import (
    MEDIA_MODE_LABELS,
    MEDIA_MODE_PHOTO,
    MEDIA_MODE_VIDEO,
    STREAM_HLS_TIME_DEFAULT,
    STREAM_IDLE_TIMEOUT_DEFAULT,
    STREAM_LIST_SIZE_DEFAULT,
    as_int,
    as_int_or,
    normalize_media_mode,
)
from hydra.core.region_image import as_timestamp
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    NC,
    clear,
    confirm,
    error,
    info,
    menu,
    prompt,
    success,
)

from hydra.ui._menus.extended_protocol_common import _application, _desired_state


def _set_enabled(state: AppState, desired: object, app: ApplicationService) -> bool:
    return app.disable_vless_cdn(state) if getattr(desired, "enabled", False) else app.enable_vless_cdn(state)


def _install(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """Спросить два имени, выпустить сертификат и поставить обновление страницы."""
    cdn_domain = prompt("CDN-домен (который вводит клиент):").strip()
    origin_host = prompt("Origin-имя (под которым CDN ходит на сервер):").strip()

    outcome = app.provision_vless_cdn(
        state,
        cdn_domain=cdn_domain,
        origin_host=origin_host,
    )
    if not outcome.ok:
        error(outcome.detail)
        prompt("Нажмите Enter")
        return

    success("Установлено")
    for line in outcome.lines():
        info(line)
    info("Настройте на стороне CDN: origin_protocol=https и origin SNI как выше.")
    prompt("Нажмите Enter")


def _set_camera(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """URL источника для видео-режима: формат, как записывать и чем отклоняется."""
    info("Источник для видео-режима: ffmpeg ремуксит его в живой HLS на /api/media/*.")
    info("")
    info("Формат — URL целиком, без кавычек и пробелов:")
    info("  https://host/live/index.m3u8     HLS-плейлист")
    info("  rtsp://user:pass@host:554/path   RTSP-камера, логин и пароль прямо в URL")
    info("")
    info("Нужен H264: H265 проиграется только в Safari, MJPEG не проиграется нигде.")
    info("Поток поднимается по требованию: первые секунды после захода уйдут на то,")
    info("чтобы ffmpeg поднялся и нарезал первый сегмент.")
    info("")
    info("Пусто — источник снимается: в видео-режиме плеер останется пустым, в фото — нет.")
    info("Ссылка внутрь сервера (127.0.0.1, 10.x, 192.168.x) и YouTube отклоняются.")
    url = prompt("URL источника (пусто — снять):").strip()
    if app.set_vless_cdn_camera(state, url):
        success("Источник снят" if not url else "Источник сохранён")
    else:
        error("Отклонено: неверная форма, YouTube, MJPEG или ссылка во внутреннюю сеть")
    prompt("Нажмите Enter")


def _media_state(mode: str, config: dict) -> list[tuple[str, str]]:
    """Строки про медиа. Без них режим — невидимая настройка, а он решает, что видит CDN."""
    if mode == MEDIA_MODE_PHOTO:
        error = str(config.get("image_refresh_error", "") or "")
        stamp = as_timestamp(config.get("image_updated_at"))
        when = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if stamp else "ещё не скачано"
        return [("Фото региона", f"{when} · ошибка: {error}" if error else when)]
    source = str(config.get("cam_source_url", "") or "").strip()
    window = as_int_or(config.get("stream_hls_list_size"), STREAM_LIST_SIZE_DEFAULT)
    idle = as_int_or(config.get("stream_idle_timeout"), STREAM_IDLE_TIMEOUT_DEFAULT)
    pause = "не гасить" if idle <= 0 else f"пауза через {idle} с"
    return [
        ("Источник", source or "НЕ ЗАДАН — плеер будет пустой"),
        ("Окно потока", f"{window} сегментов · {pause}"),
    ]


def _set_mode(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """Режим медиа: выбор явный, с ценой каждого варианта в описании."""
    current = normalize_media_mode(_desired_state(state, PROTOCOL_NAME).config.get("media_mode"))
    options = [
        (
            "1",
            f"{'●' if current == MEDIA_MODE_VIDEO else '○'} Видео — ретрансляция камеры",
            "Страница играет живой поток (пункт 5 — источник, 7 — настройки). Даёт"
            " медиатрафик на origin — то, ради чего заглушка и существует.",
        ),
        (
            "2",
            f"{'●' if current == MEDIA_MODE_PHOTO else '○'} Фото — картинка региона",
            "Плеера нет, только фото региона (обновляется раз в 12 часов). Медиатрафика нет:"
            " страница живая, но объём VLESS она больше не объясняет.",
        ),
        ("0", "↩ Назад", ""),
    ]
    choice = menu(options, "Режим медиа")
    if choice not in {"1", "2"}:
        return
    mode = MEDIA_MODE_VIDEO if choice == "1" else MEDIA_MODE_PHOTO
    if app.set_vless_cdn_mode(state, mode):
        success(f"Режим: {MEDIA_MODE_LABELS[mode]}")
    else:
        error("Не удалось сменить режим")
    prompt("Нажмите Enter")


def _set_stream(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """Настройки потока — три числа, от которых зависят запас и трафик.

    Текущий режим работы показываем здесь, а не в панели: чтобы его узнать, надо
    спросить systemd, и делать это на каждой отрисовке меню незачем.
    """
    desired = _desired_state(state, PROTOCOL_NAME)
    config = desired.config
    hls_time = max(1, as_int_or(config.get("stream_hls_time"), STREAM_HLS_TIME_DEFAULT))
    list_size = max(3, as_int_or(config.get("stream_hls_list_size"), STREAM_LIST_SIZE_DEFAULT))
    idle = max(0, as_int_or(config.get("stream_idle_timeout"), STREAM_IDLE_TIMEOUT_DEFAULT))

    status = app.media_status()
    where = "работает" if status.get("active") else "спит"
    age = status.get("playlist_age")
    if isinstance(age, (int, float)):
        where += f", плейлисту {age:.0f} с"
    info(f"Поток сейчас: {where}")
    info("")

    options = [
        (
            "1",
            f"Сегмент: {hls_time} с",
            "Минимум, а не приказ: ffmpeg режет только по кейфреймам источника.",
        ),
        (
            "2",
            f"Окно плейлиста: {list_size} сегментов",
            "Больше окно — терпимее к задержке через CDN и больше места на диске.",
        ),
        (
            "3",
            f"Пауза без зрителя: {'никогда' if idle <= 0 else str(idle) + ' с'}",
            "Сколько ждать без обращений, прежде чем погасить поток. Ноль — не гасить.",
        ),
        ("0", "↩ Назад", ""),
    ]
    choice = menu(options, "Настройки потока")
    fields = {
        "1": ("hls_time", "Длительность сегмента, с", hls_time),
        "2": ("list_size", "Размер окна, сегментов", list_size),
        "3": ("idle_timeout", "Пауза без зрителя, с (0 — не гасить)", idle),
    }
    if choice not in fields:
        return
    field, label, current = fields[choice]
    answer = prompt(f"{label} [{current}]:").strip()
    if not answer:
        return
    # object, а не int: в поле попадает ещё не разобранный ответ оператора — его
    # проверяет контракт, а не этот экран.
    values: dict[str, object] = {"hls_time": hls_time, "list_size": list_size, "idle_timeout": idle}
    values[field] = answer
    if app.set_vless_cdn_stream(
        state,
        hls_time=values["hls_time"],
        list_size=values["list_size"],
        idle_timeout=values["idle_timeout"],
    ):
        success("Сохранено, службы переустановлены")
    else:
        error("Не удалось сохранить настройки")
    prompt("Нажмите Enter")


def _menu_vless_cdn(
    state: AppState,
    plugin: BasePlugin,
    app: ApplicationService | None = None,
) -> None:
    """Меню протокола: два имени, профиль клиента и страница-прикрытие."""
    app = _application(app)

    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, PROTOCOL_NAME)
        clear()

        config = desired.config
        mode = normalize_media_mode(config.get("media_mode"))
        details = [
            ("CDN-домен", str(config.get("cdn_domain", "") or "—")),
            ("Origin-имя", str(config.get("origin_host", "") or "—")),
            ("XHTTP путь", str(config.get("xhttp_path", "") or "—")),
            ("Порт ядра", str(config.get("core_port", 0) or "—")),
            ("Сертификат", str(config.get("cert_file", "") or "—")),
            ("Регион origin-сервера", str(config.get("region_city", "") or "—")),
            ("Режим медиа", MEDIA_MODE_LABELS[mode]),
            *_media_state(mode, config),
        ]
        protocol_status_panel(
            PROTOCOL_NAME,
            installed=bool(config.get("cert_file")),
            enabled=desired.enabled,
            running=bool(desired.enabled and config.get("cert_file")),
            port=as_int(config.get("core_port")),
            details=details,
            display_name=plugin.meta.display_name,
        )

        options: list[tuple[str, str, str]] = []
        if config.get("cert_file"):
            options.append(
                (
                    "1",
                    "⏸️  Выключить" if desired.enabled else "▶️  Включить",
                    "Отключить протокол" if desired.enabled else "Активировать протокол",
                ),
            )
            options.extend(
                [
                    ("5", "📹 Источник потока", "URL для видео-режима: HLS-плейлист или RTSP"),
                    ("6", "🎞 Режим медиа", "Видео (живой поток) или фото региона — что видит посетитель"),
                    ("7", "⚙️ Настройки потока", "Сегмент, окно плейлиста, пауза без зрителя"),
                    ("8", "🔄 Переустановить", "Заменить домены и выпустить сертификат заново"),
                    ("9", "❌ Удалить", "Протокол, страница и таймер"),
                ],
            )
        else:
            options.append(
                ("1", "🔧 Установить", "Спросить CDN-домен и origin-имя"),
            )

        options.append(("0", "↩ Назад", ""))
        choice = menu(
            options,
            protocol_menu_title(PROTOCOL_NAME, plugin.meta.display_name),
        )

        if choice == "0":
            return
        if choice == "1" and not config.get("cert_file"):
            _install(state, plugin, app)
        elif choice == "1":
            if _set_enabled(state, desired, app):
                success("Отключено" if desired.enabled else "Активировано")
            else:
                error("Не удалось изменить состояние протокола")
            prompt("Нажмите Enter")
        elif choice == "5" and config.get("cert_file"):
            _set_camera(state, plugin, app)
        elif choice == "6" and config.get("cert_file"):
            _set_mode(state, plugin, app)
        elif choice == "7" and config.get("cert_file"):
            _set_stream(state, plugin, app)
        elif choice == "8":
            if confirm("Переустановить протокол с новыми доменами?", default=False):
                _install(state, plugin, app)
        elif choice == "9":
            if not confirm("Удалить протокол, страницу и таймер?", default=False):
                continue
            if app.uninstall_vless_cdn(state):
                success("Удалено")
                prompt("Нажмите Enter")
                return
            error("Ошибка удаления")
            prompt("Нажмите Enter")


__all__ = ["_menu_vless_cdn"]
