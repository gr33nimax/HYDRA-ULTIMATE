"""Static qWDTT help screens."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def show_guide() -> None:
    while True:
        facade.clear()
        facade.title("Руководство по qWDTT")
        choice = facade.menu(
            [
                ("1", "📱 Приложение на Android", ""),
                ("2", "🔑 Получение VK-хеша звонка", ""),
                ("3", "🤖 Настройка Telegram-бота", ""),
                ("0", "↩ Назад", ""),
            ],
            "РУКОВОДСТВО",
        )
        if choice == "0":
            return
        if choice == "1":
            facade._guide_android()
        elif choice == "2":
            facade._guide_vk_hash()
        elif choice == "3":
            facade._guide_telegram()


def guide_android() -> None:
    facade.clear()
    print(
        f"""
  {facade.BOLD}{facade.CYAN}📱 ПРИЛОЖЕНИЕ qWDTT{facade.NC}

  qWDTT — форк нетРКН с поддержкой WireGuard/TURN профилей и qwdtt:// ссылок.

  {facade.BOLD}Скачать APK:{facade.NC}
  Скачайте APK с официального релиза на GitHub:
  {facade.YELLOW}https://github.com/SpaceNeuroX/proxy-turn-vk-android/releases{facade.NC}

  Установите на устройство, разрешив установку из внешних источников.
  Требуется Android 8.0+.
""",
    )
    facade.prompt("Нажмите Enter...")


def guide_vk_hash() -> None:
    facade.clear()
    print(
        f"""
  {facade.BOLD}{facade.CYAN}🔑 ПОЛУЧЕНИЕ VK-ХЕША ЗВОНКА{facade.NC}

  Хеш звонка — часть ссылки-приглашения после /join/ в звонках ВКонтакте.

  {facade.BOLD}Инструкция:{facade.NC}
  1. В приложении VK перейдите в «Звонки» → «Создать звонок».
  2. Скопируйте ссылку вида https://vk.com/call/join/ХЕШ.
  3. Скопируйте часть после /join/ — это и есть ваш хеш.

  Можно указать до 4 хешей через запятую для балансировки нагрузки.
  При выходе выбирайте «Просто выйти», а не «Завершить для всех».
""",
    )
    facade.prompt("Нажмите Enter...")


def guide_telegram() -> None:
    facade.clear()
    print(
        f"""
  {facade.BOLD}{facade.CYAN}🤖 НАСТРОЙКА TELEGRAM-БОТА{facade.NC}

  Telegram-бот позволяет управлять паролями из мессенджера без SSH.

  {facade.BOLD}Инструкция:{facade.NC}
  1. Напишите @BotFather и создайте нового бота (/newbot).
  2. Получите Token вашего бота.
  3. Узнайте Chat ID через @userinfobot или аналогичного бота.
  4. Укажите эти данные при установке/настройке qWDTT.

  {facade.BOLD}Команды бота:{facade.NC}
  • /new  — создать временный пароль
  • /list — список активных паролей и управление устройствами
""",
    )
    facade.prompt("Нажмите Enter...")
