"""Certificate inventory and explicit maintenance beside background-service settings."""

from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.certificate_management import IssuedCertificate
from hydra.ui.tui import clear, confirm, error, info, kv, menu, panel, prompt, success, warn


_STATUS = {
    "ok": "действителен",
    "expiring": "скоро истекает",
    "expired": "истёк",
    "missing": "файлы отсутствуют",
    "unreadable": "не удалось прочитать",
}


def _menu_certificates(state: AppState, app: ApplicationService) -> None:
    del state
    while True:
        clear()
        try:
            certificates = app.certificates.inventory()
        except Exception as exc:
            error(f"Не удалось получить сертификаты: {exc}")
            prompt("Нажмите Enter")
            return
        panel(
            "TLS-сертификаты этого VPS",
            [
                kv("В списке:", str(len(certificates))),
                "Сертификаты Certbot, в том числе неиспользуемые, и настроенные внешние TLS-файлы.",
            ],
        )
        choices = {str(index): certificate for index, certificate in enumerate(certificates, 1)}
        items = [
            (
                key,
                f"{certificate.name} — {_STATUS.get(certificate.status, certificate.status)}",
                f"До: {certificate.expires[:10] or 'неизвестно'}; используется: {', '.join(certificate.used_by) or 'не назначен HYDRA'}",
            )
            for key, certificate in choices.items()
        ]
        choice = menu(
            [*items, ("r", "Обновить список", "Прочитать текущее состояние без изменений"), ("0", "↩ Назад", "")],
            "СЕРТИФИКАТЫ",
        )
        if choice == "0":
            return
        if choice in choices:
            _certificate_detail(choices[choice], app)


def _certificate_detail(certificate: IssuedCertificate, app: ApplicationService) -> None:
    clear()
    panel(
        f"Сертификат: {certificate.name}",
        [
            kv("Домены:", ", ".join(certificate.domains) or "не удалось прочитать"),
            kv("Статус:", _STATUS.get(certificate.status, certificate.status)),
            kv("Действует до:", certificate.expires or "неизвестно"),
            kv("Осталось дней:", str(certificate.days_left) if certificate.days_left is not None else "неизвестно"),
            kv("Файл:", certificate.certificate or "не настроен"),
            kv("Назначен:", ", ".join(certificate.used_by) or "не назначен HYDRA; другие службы не проверяются"),
            kv("Управление:", "Certbot" if certificate.managed else "внешний TLS-материал, только просмотр"),
        ],
    )
    if not certificate.managed:
        prompt("Нажмите Enter")
        return
    choice = menu(
        [
            ("1", "Перевыпустить", "Принудительный выпуск, даже если сертификат ещё действителен"),
            ("2", "Удалить", "Удалить lineage Certbot с подтверждением имени; не отзыв у CA"),
            ("0", "↩ Назад", ""),
        ],
        "УПРАВЛЕНИЕ СЕРТИФИКАТОМ",
    )
    if choice == "1":
        warn("Перевыпуск обращается к CA и расходует лимиты выпуска. Возможен краткий перерыв TLS-служб.")
        if not confirm(f"Перевыпустить {certificate.name}?"):
            return
        info("Перевыпуск сертификата...")
        result = app.certificates.reissue(certificate.name)
    elif choice == "2":
        if certificate.used_by:
            warn("Сертификат назначен: " + ", ".join(certificate.used_by))
        warn(
            "Удаление файлов может сломать TLS после reload/перезапуска. Другие службы на VPS также могут использовать сертификат."
        )
        warn("Настройки HYDRA и службы не отключаются. Автопроверка или apply могут выпустить сертификат заново.")
        typed = prompt(f"Для удаления введите точное имя {certificate.name} (пусто — отмена)")
        if typed != certificate.name:
            warn("Имя не совпало, удаление отменено")
            prompt("Нажмите Enter")
            return
        result = app.certificates.delete(certificate.name, confirmation=typed)
    else:
        return
    if result.ok:
        success(result.message)
    else:
        error(result.message or "Операция с сертификатом не выполнена")
    prompt("Нажмите Enter")
