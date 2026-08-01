"""Interactive setup for the four-call VK headless creator."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _result(value: object) -> tuple[bool, str]:
    if isinstance(value, tuple) and len(value) == 2:
        return bool(value[0]), str(value[1] or "")
    return bool(value), ""


def setup_headless_creator(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Настройка VK headless creator")
    facade.panel(
        "HEADLESS CREATOR",
        [
            "HYDRA скачает подходящий verified release и установит headless-vk-creator.",
            "Будут запущены четыре независимых VK-звонка.",
            "Файл VK cookies: /etc/hydra/cookiesvk/cookies-vk.json",
            "Поддерживается экспортированный Creator JSON, в том числе многострочный.",
            "Файл защищается правами 0600 и не попадает в state.",
        ],
    )
    protocol = facade.get_protocol(state, "wdtt")
    was_enabled = bool(protocol.config.get("headless_enabled", False))
    protocol.config["headless_enabled"] = True
    app.admin.save_state(state)
    facade.info(
        "Устанавливаю headless creator и запускаю четыре инстанса; "
        "ожидание ссылок может занять до минуты...",
    )
    try:
        result = app.plugin_action(
            "wdtt",
            "setup_headless_creator",
            state=state,
        )
        ok, message = _result(result)
    except Exception as exc:
        ok, message = False, str(exc)
    if not ok:
        protocol.config["headless_enabled"] = was_enabled
        app.admin.save_state(state)
        facade.error(message or "Не удалось запустить headless creator")
        facade.prompt("Нажмите Enter...")
        return
    link = str(app.plugin_query("wdtt", "headless_creator_link"))
    facade.success("Четыре звонка созданы, мастер-ссылка qWDTT обновлена.")
    if link:
        facade.panel(
            "ЕДИНАЯ МАСТЕР-ССЫЛКА",
            ["Используйте эту ссылку для qWDTT-конфигурации:", link],
        )
        facade._save_link_to_file(link, "qwdtt_link.txt", app)
    facade.prompt("Нажмите Enter...")


__all__ = ["setup_headless_creator"]
