"""
hydra/ui/menus.py — Главное меню и подменю.
"""
from __future__ import annotations

import json
import sys
import uuid as _uuid
from datetime import datetime

from hydra.core.state import (
    AppState, User, load_state, save_state, find_user, add_user,
)
from hydra.core.singbox import (
    install as install_singbox,
    generate_config, write_config, reload as reload_singbox,
    start as start_singbox, is_running, status_text,
    is_installed as singbox_installed,
)
from hydra.plugins.registry import (
    get_all, get as get_plugin, get_enabled, collect_fragments,
    install_all, status_all,
)
from hydra.plugins.base import ConfigFragment
from hydra.core.systemd import install_service, install_timer, remove_unit
from hydra.services.subscriptions.generator import start_sub_server
from hydra.services.traffic import collect_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, NC,
)

_sub_server = None


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню
# ═════════════════════════════════════════════════════════════════════════════

def main_menu(state: AppState):
    """Точка входа — главное меню HYDRA."""
    global _sub_server

    # Запускаем сервер подписок в фоне
    if _sub_server is None:
        try:
            _sub_server = start_sub_server(state)
        except Exception:
            pass

    while True:
        clear()
        print(BANNER)

        sb_status = status_text() if singbox_installed() else f"{YELLOW}Sing-Box не установлен{NC}"
        print(f"  {sb_status}")
        print()

        choice = menu(
            [
                ("1", "⚙️  Ядро и система", "Установка Sing-Box, зависимости, тюнинг"),
                ("2", "🧩 Протоколы", "NaiveProxy, Mieru, AmneziaWG, DNSCrypt, WARP"),
                ("3", "👥 Пользователи и подписки", "Добавление, удаление, лимиты, TTL"),
                ("4", "🤖 Telegram-боты", "Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг", "Трафик, статус протоколов, логи"),
                ("6", "🛡️ Безопасность", "GeoIP, fail2ban, honeypot"),
                ("0", "🚪 Выход", ""),
            ],
            "HYDRA MULTI-PROXY MANAGER",
        )

        if choice == "0":
            print(f"\n{GREEN}До свидания! 👋{NC}")
            sys.exit(0)
        elif choice == "1":
            menu_core(state)
        elif choice == "2":
            menu_protocols(state)
        elif choice == "3":
            menu_users(state)
        elif choice == "4":
            menu_telegram(state)
        elif choice == "5":
            menu_monitoring(state)
        elif choice == "6":
            menu_security(state)


# ═════════════════════════════════════════════════════════════════════════════
#  1. Ядро и система
# ═════════════════════════════════════════════════════════════════════════════

def menu_core(state: AppState):
    while True:
        clear()
        installed = singbox_installed()
        running = is_running()
        status_icon = "✅" if running else ("⚠️" if installed else "❌")

        choice = menu(
            [
                ("1", f"{status_icon} Sing-Box", status_text()),
                ("2", "📦 Установить все плагины", "Загрузить Caddy, Mieru, AWG, WARP..."),
                ("3", "🔄 Применить конфиг", "Пересобрать и перезагрузить Sing-Box"),
                ("0", "↩ Назад", ""),
            ],
            "ЯДРО И СИСТЕМА",
        )

        if choice == "0":
            return
        elif choice == "1":
            if not installed:
                info("Устанавливаю Sing-Box...")
                if install_singbox():
                    success("Sing-Box установлен")
                    if start_singbox():
                        success("Sing-Box запущен")
                else:
                    error("Ошибка установки Sing-Box")
            else:
                if running:
                    info(f"Sing-Box запущен. Версия: {status_text()}")
                else:
                    warn("Sing-Box остановлен. Запускаю...")
                    start_singbox()
            prompt("Нажмите Enter для продолжения")
        elif choice == "2":
            info("Устанавливаю все плагины...")
            results = install_all(state)
            for name, ok in results.items():
                (success if ok else error)(f"  {name}: {'OK' if ok else 'FAIL'}")
            prompt("Нажмите Enter для продолжения")
        elif choice == "3":
            info("Собираю конфиг Sing-Box...")
            fragments = collect_fragments(state)
            # Конвертируем ConfigFragment → dict
            frag_dicts = {}
            for name, frag in fragments.items():
                frag_dicts[name] = {
                    "inbounds": frag.inbounds,
                    "outbounds": frag.outbounds,
                    "route_rules": frag.route_rules,
                }
            config = generate_config(state, frag_dicts)
            if write_config(config):
                success("Конфиг записан")
                if reload_singbox():
                    success("Sing-Box перезагружен")
                else:
                    warn("Не удалось перезагрузить Sing-Box. Попробуйте запустить вручную.")
            else:
                error("Ошибка валидации конфига")
            prompt("Нажмите Enter для продолжения")


# ═════════════════════════════════════════════════════════════════════════════
#  2. Протоколы
# ═════════════════════════════════════════════════════════════════════════════

def menu_protocols(state: AppState):
    while True:
        clear()
        plugins = get_all()
        options: list[tuple[str, str, str]] = []

        for i, plugin in enumerate(plugins, 1):
            status = plugin.status()
            icon = "✅" if status.running else ("⚠️" if status.installed else "❌")
            enabled = "вкл" if status.enabled else "выкл"
            options.append((
                str(i),
                f"{icon} {plugin.meta.name} [{enabled}]",
                plugin.meta.description,
            ))

        options.append(("-", "", ""))
        options.append(("A", "🔄 Применить конфиг и перезагрузить", ""))
        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "ПРОТОКОЛЫ (ПЛАГИНЫ)")

        if choice == "0":
            return
        elif choice.upper() == "A":
            fragments = collect_fragments(state)
            frag_dicts = {}
            for name, frag in fragments.items():
                frag_dicts[name] = {
                    "inbounds": frag.inbounds,
                    "outbounds": frag.outbounds,
                    "route_rules": frag.route_rules,
                }
            config = generate_config(state, frag_dicts)
            if write_config(config):
                success("Конфиг применён")
                reload_singbox()
            else:
                error("Ошибка конфига")
            prompt("Нажмите Enter")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(plugins):
                    menu_plugin(state, plugins[idx])
            except ValueError:
                pass


def menu_plugin(state: AppState, plugin):
    """Подменю конкретного плагина."""
    while True:
        clear()
        status = plugin.status()
        running_icon = "✅" if status.running else "❌"
        enabled_icon = "✅" if status.enabled else "❌"

        proto = state.protocols.get(plugin.meta.name)

        choice = menu(
            [
                ("1", f"Установлен: {running_icon if status.installed else '❌'}", ""),
                ("2", f"Включён: {enabled_icon}", ""),
                ("3", "🔧 Установить/обновить", "Загрузить зависимости"),
                ("4", "▶️ Включить", "Активировать протокол"),
                ("5", "⏸️ Выключить", "Деактивировать протокол"),
                ("6", "🗑 Удалить", "Полностью удалить"),
                ("0", "↩ Назад", ""),
            ],
            f"ПЛАГИН: {plugin.meta.name.upper()}",
        )

        if choice == "0":
            return
        elif choice == "3":
            if plugin.install():
                success(f"{plugin.meta.name} установлен")
            else:
                error(f"Ошибка установки {plugin.meta.name}")
            prompt("Нажмите Enter")
        elif choice == "4":
            if not status.installed:
                warn("Сначала установите плагин (пункт 3)")
            else:
                plugin.on_enable(state)
                if proto:
                    proto.enabled = True
                save_state(state)
                success(f"{plugin.meta.name} включён")
            prompt("Нажмите Enter")
        elif choice == "5":
            plugin.on_disable(state)
            if proto:
                proto.enabled = False
            save_state(state)
            success(f"{plugin.meta.name} выключен")
            prompt("Нажмите Enter")
        elif choice == "6":
            plugin.uninstall()
            if proto:
                proto.enabled = False
                proto.installed = False
            save_state(state)
            success(f"{plugin.meta.name} удалён")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  3. Пользователи и подписки
# ═════════════════════════════════════════════════════════════════════════════

def menu_users(state: AppState):
    while True:
        clear()
        user_count = len(state.users)
        active_count = sum(1 for u in state.users if not u.blocked)

        choice = menu(
            [
                ("1", "📋 Список пользователей", f"Всего: {user_count}, активно: {active_count}"),
                ("2", "➕ Добавить пользователя", "Создать новую учётную запись"),
                ("3", "🗑 Удалить пользователя", "Удалить по email"),
                ("4", "🔒 Заблокировать", "Заблокировать по email"),
                ("5", "🔓 Разблокировать", "Разблокировать по email"),
                ("6", "📊 Лимиты трафика", "Установить лимит (GB)"),
                ("7", "⏰ Срок действия (TTL)", "Установить дату окончания"),
                ("0", "↩ Назад", ""),
            ],
            "ПОЛЬЗОВАТЕЛИ И ПОДПИСКИ",
        )

        if choice == "0":
            return
        elif choice == "1":
            _show_users(state)
        elif choice == "2":
            _add_user(state)
        elif choice == "3":
            _delete_user(state)
        elif choice == "4":
            _block_user(state, True)
        elif choice == "5":
            _block_user(state, False)
        elif choice == "6":
            _set_limit(state)
        elif choice == "7":
            _set_ttl(state)


def _show_users(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return

    print(f"\n{BOLD}{CYAN}Список пользователей:{NC}\n")
    for u in state.users:
        icon = "🔴" if u.blocked else "🟢"
        limit = f"{u.traffic_limit_gb} GB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        print(f"  {icon} {u.email}")
        print(f"     UUID: {u.uuid[:16]}...")
        print(f"     Лимит: {limit}  |  TTL: {ttl}")
        print()
    prompt("Нажмите Enter")


def _add_user(state: AppState):
    email = prompt("Email пользователя")
    if not email:
        return
    if find_user(state, email):
        warn(f"Пользователь {email} уже существует.")
        prompt("Нажмите Enter")
        return

    limit = prompt("Лимит трафика (GB, 0 = безлимит)", "0")
    ttl = prompt("Срок действия (дней, 0 = бессрочно)", "0")

    user = User(
        email=email,
        uuid=str(_uuid.uuid4()),
        traffic_limit_gb=float(limit) if limit else 0,
        expiry_date=(
            datetime.now().isoformat() if int(ttl) <= 0
            else datetime.fromtimestamp(
                datetime.now().timestamp() + int(ttl) * 86400
            ).isoformat()
        ),
        created_at=datetime.now().isoformat(),
    )
    add_user(state, user)
    save_state(state)
    success(f"Пользователь {email} создан.")


def _delete_user(state: AppState):
    email = prompt("Email пользователя для удаления")
    user = find_user(state, email)
    if not user:
        warn("Пользователь не найден.")
    else:
        state.users.remove(user)
        save_state(state)
        success(f"Пользователь {email} удалён.")
    prompt("Нажмите Enter")


def _block_user(state: AppState, block: bool):
    email = prompt("Email пользователя")
    user = find_user(state, email)
    if not user:
        warn("Пользователь не найден.")
    else:
        user.blocked = block
        save_state(state)
        action = "заблокирован" if block else "разблокирован"
        success(f"Пользователь {email} {action}.")
    prompt("Нажмите Enter")


def _set_limit(state: AppState):
    email = prompt("Email пользователя")
    user = find_user(state, email)
    if not user:
        warn("Пользователь не найден.")
    else:
        gb = prompt("Лимит (GB, 0 = безлимит)", str(user.traffic_limit_gb))
        user.traffic_limit_gb = float(gb) if gb else 0
        save_state(state)
        success(f"Лимит для {email}: {user.traffic_limit_gb or '∞'} GB")
    prompt("Нажмите Enter")


def _set_ttl(state: AppState):
    email = prompt("Email пользователя")
    user = find_user(state, email)
    if not user:
        warn("Пользователь не найден.")
    else:
        days = prompt("Срок (дней от сегодня, 0 = бессрочно)", "0")
        if int(days) > 0:
            user.expiry_date = datetime.fromtimestamp(
                datetime.now().timestamp() + int(days) * 86400
            ).isoformat()
        else:
            user.expiry_date = ""
        save_state(state)
        success(f"TTL для {email}: {user.expiry_date[:10] if user.expiry_date else '∞'}")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  4. Telegram-боты
# ═════════════════════════════════════════════════════════════════════════════

def menu_telegram(state: AppState):
    while True:
        clear()
        tg = state.telegram

        choice = menu(
            [
                ("1", f"🔑 Admin-токен: {'✓' if tg.admin_token else '✗'}", ""),
                ("2", f"💬 Admin Chat ID: {tg.admin_chat_id or '✗'}", ""),
                ("3", f"🤖 Bot-токен: {'✓' if tg.bot_token else '✗'}", ""),
                ("4", "▶️ Запустить ботов", "Установить systemd-сервисы"),
                ("5", "⏸️ Остановить ботов", ""),
                ("0", "↩ Назад", ""),
            ],
            "TELEGRAM-БОТЫ",
        )

        if choice == "0":
            return
        elif choice == "1":
            token = prompt("Токен admin-бота")
            if token:
                state.telegram.admin_token = token
                save_state(state)
                success("Токен сохранён")
            prompt("Нажмите Enter")
        elif choice == "2":
            chat_id = prompt("Admin Chat ID (число)")
            if chat_id:
                state.telegram.admin_chat_id = chat_id
                save_state(state)
                success("Chat ID сохранён")
            prompt("Нажмите Enter")
        elif choice == "3":
            token = prompt("Токен клиентского бота")
            if token:
                state.telegram.bot_token = token
                save_state(state)
                success("Токен сохранён")
            prompt("Нажмите Enter")
        elif choice == "4":
            _install_bots(state)
        elif choice == "5":
            remove_unit("hydra-tg-admin")
            remove_unit("hydra-tg-bot")
            state.telegram.admin_enabled = False
            state.telegram.bot_enabled = False
            save_state(state)
            success("Боты остановлены")
            prompt("Нажмите Enter")


def _install_bots(state: AppState):
    if not state.telegram.admin_token:
        error("Сначала укажите admin-токен (пункт 1)")
        prompt("Нажмите Enter")
        return

    admin_svc = f"""[Unit]
Description=HYDRA Telegram Admin Bot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_admin_bot; run_admin_bot('{state.telegram.admin_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    install_service("hydra-tg-admin", admin_svc)
    state.telegram.admin_enabled = True
    success("Admin-бот запущен")

    if state.telegram.bot_token:
        client_svc = f"""[Unit]
Description=HYDRA Telegram Client Bot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_client_bot; run_client_bot('{state.telegram.bot_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        install_service("hydra-tg-bot", client_svc)
        state.telegram.bot_enabled = True
        success("Client-бот запущен")

    save_state(state)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  5. Мониторинг
# ═════════════════════════════════════════════════════════════════════════════

def menu_monitoring(state: AppState):
    while True:
        clear()

        choice = menu(
            [
                ("1", "📊 Трафик по пользователям", ""),
                ("2", "🔌 Статус протоколов", ""),
                ("3", "🔄 Установить Sync Agent", "systemd timer каждые 5 мин"),
                ("0", "↩ Назад", ""),
            ],
            "МОНИТОРИНГ",
        )

        if choice == "0":
            return
        elif choice == "1":
            _show_traffic(state)
        elif choice == "2":
            _show_status()
        elif choice == "3":
            _install_sync_agent(state)


def _show_traffic(state: AppState):
    clear()
    traffic = collect_traffic(state)
    print(f"\n{BOLD}{CYAN}Трафик по пользователям:{NC}\n")
    for user in state.users:
        used = traffic.get(user.email, user.traffic_used_bytes)
        used_gb = used / 1073741824
        limit_str = f"/ {user.traffic_limit_gb} GB" if user.traffic_limit_gb else "/ ∞"
        bar = _progress(used, int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0)
        print(f"  {user.email}: {used_gb:.2f} GB {limit_str}")
        print(f"  {bar}")
        print()
    prompt("Нажмите Enter")


def _show_status():
    clear()
    print(f"\n{BOLD}{CYAN}Статус протоколов:{NC}\n")
    for name, s in status_all().items():
        icon = "✅" if s["running"] else ("⚠️" if s["installed"] else "❌")
        print(f"  {icon} {name}: порт {s['port']}")
    print()
    prompt("Нажмите Enter")


def _install_sync_agent(state: AppState):
    svc = """[Unit]
Description=HYDRA Sync Agent
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -m hydra.services.sync_agent
"""
    tmr = """[Unit]
Description=HYDRA Sync Agent Timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
"""
    install_timer("hydra-sync-agent", svc, tmr)
    success("Sync Agent установлен (каждые 5 минут)")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  6. Безопасность
# ═════════════════════════════════════════════════════════════════════════════

def menu_security(state: AppState):
    while True:
        clear()
        sec = state.security

        choice = menu(
            [
                ("1", f"🌍 GeoIP-блокировка: {'✅' if sec.geoip_block_enabled else '❌'}", "Блокировка входящих из РФ"),
                ("2", f"🛡️ Fail2ban: {'✅' if sec.fail2ban_enabled else '❌'}", "Защита от перебора"),
                ("3", f"🪤 Honeypot: {'✅' if sec.honeypot_enabled else '❌'}", "Порты-ловушки"),
                ("0", "↩ Назад", ""),
            ],
            "БЕЗОПАСНОСТЬ",
        )

        if choice == "0":
            return
        elif choice == "1":
            sec.geoip_block_enabled = not sec.geoip_block_enabled
            save_state(state)
            status = "включена" if sec.geoip_block_enabled else "выключена"
            success(f"GeoIP-блокировка {status}")
            prompt("Нажмите Enter")
        elif choice == "2":
            sec.fail2ban_enabled = not sec.fail2ban_enabled
            save_state(state)
            status = "включён" if sec.fail2ban_enabled else "выключен"
            success(f"Fail2ban {status}")
            prompt("Нажмите Enter")
        elif choice == "3":
            sec.honeypot_enabled = not sec.honeypot_enabled
            save_state(state)
            status = "включён" if sec.honeypot_enabled else "выключен"
            success(f"Honeypot {status}")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════

def _progress(used: int, limit: int, width: int = 20) -> str:
    if limit <= 0:
        return f"[{'█' * width}] ∞"
    pct = min(used / limit, 1.0)
    filled = int(pct * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {pct:.0%}"
