"""
hydra/ui/menus.py — Главное меню и подменю.
"""
from __future__ import annotations

import json
import subprocess
import sys
import uuid as _uuid
from datetime import datetime
from pathlib import Path

from hydra.core.state import (
    AppState, User, load_state, save_state, find_user, add_user, get_protocol,
)
from hydra.core.singbox import (
    install as install_singbox,
    generate_config, write_config, reload as reload_singbox,
    start as start_singbox, is_running, status_text,
    is_installed as singbox_installed, get_version as singbox_version,
)
from hydra.plugins.registry import (
    get_all, get_enabled, collect_fragments,
    status_all,
)
from hydra.core.systemd import install_service, install_timer, remove_unit
from hydra.core import orchestrator
from hydra.services.subscriptions.generator import start_sub_server
from hydra.services.traffic import collect_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    BANNER, GREEN, CYAN, YELLOW, RED, BLUE, BOLD, DIM, WHITE, NC,
)

_sub_server = None


def _bar(value: float, maximum: float, width: int = 18) -> str:
    if maximum <= 0:
        return f"[{'█' * width}] ∞"
    pct = min(value / maximum, 1.0)
    filled = int(pct * width)
    return f"{GREEN}[{'█' * filled}{DIM}{'░' * (width - filled)}{NC}] {pct:.0%}"


def _bytes(v: int) -> str:
    return f"{v / 1073741824:.2f} GB"


def _ok(ok: bool) -> str:
    return f"{GREEN}✓{NC}" if ok else f"{RED}✗{NC}"


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню
# ═════════════════════════════════════════════════════════════════════════════

def main_menu(state: AppState):
    global _sub_server
    if _sub_server is None:
        try:
            _sub_server = start_sub_server(state)
        except Exception:
            pass

    while True:
        clear()
        print(BANNER)

        sb_ok = singbox_installed() and is_running()
        plugins = status_all()
        active_p = sum(1 for s in plugins.values() if s["running"])
        total_p = len(plugins)
        u_active = sum(1 for u in state.users if not u.blocked)

        panel("Состояние", [
            kv("Sing-Box:", f"{_ok(sb_ok)}  {singbox_version() or 'не установлен'}"),
            kv("Протоколов:", f"{GREEN}{active_p}{NC}/{total_p} запущено"),
            kv("Пользователей:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ])

        choice = menu(
            [
                ("1", "⚙️  Ядро и система",     f"Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"NaiveProxy, Mieru, AmneziaWG, DNSCrypt, WARP  [{active_p}/{total_p}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       f"Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          f"Трафик, статус, sync-агент"),
                ("6", "🛡️  Безопасность",       f"GeoIP, fail2ban, honeypot"),
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
        ok_i = singbox_installed()
        ok_r = is_running()
        ver = singbox_version()

        panel("Sing-Box", [
            kv("Статус:", f"{_ok(ok_r)} {'запущен' if ok_r else 'остановлен'}"),
            kv("Версия:", ver or "—"),
            kv("Конфиг:", f"{DIM}/etc/sing-box/config.json{NC}"),
            kv("Лог:", f"{DIM}/var/log/sing-box/sing-box.log{NC}"),
        ])

        choice = menu(
            [
                ("1", "📦 Установить Sing-Box" if not ok_i else "🔄 Переустановить",
                 "Официальный репозиторий / GitHub .deb"),
                ("2", "▶️  Запустить" if not ok_r else "⏸️  Остановить", ""),
                ("3", "🔄 Применить конфиг",
                 "Собрать /etc/sing-box/config.json и перезагрузить"),
                ("0", "↩ Назад", ""),
            ],
            "ЯДРО И СИСТЕМА",
        )

        if choice == "0":
            return
        elif choice == "1":
            info("Устанавливаю Sing-Box...")
            if install_singbox():
                success(f"Sing-Box {singbox_version()} установлен")
                if start_singbox():
                    success("Запущен")
            else:
                error("Не удалось установить")
            prompt("Нажмите Enter")
        elif choice == "2":
            if ok_r:
                from hydra.core.singbox import stop
                stop()
                success("Остановлен")
            else:
                if start_singbox():
                    success("Запущен")
                else:
                    error("Не удалось запустить. Проверьте: systemctl status sing-box")
            prompt("Нажмите Enter")
        elif choice == "3":
            info("Собираю конфиг...")
            cfg = generate_config(state, collect_fragments(state))
            if write_config(cfg):
                success("Конфиг записан")
                if reload_singbox():
                    success("Sing-Box перезагружен")
                else:
                    warn("Перезагрузка не удалась")
            else:
                error("Ошибка валидации конфига")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  2. Протоколы
# ═════════════════════════════════════════════════════════════════════════════

def menu_protocols(state: AppState):
    while True:
        clear()
        plugins = get_all()

        proto_lines = []
        for p in plugins:
            s = p.status()
            ico = f"{GREEN}●{NC}" if s.running else (f"{YELLOW}●{NC}" if s.installed else f"{DIM}●{NC}")
            port = f":{s.port}" if s.port else ""
            st = "вкл" if s.enabled else "выкл"
            proto_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st:>4}{NC}  порт{port}")
        panel("Протоколы", proto_lines)

        opts = []
        for i, p in enumerate(plugins, 1):
            s = p.status()
            ico = f"{GREEN}✓{NC}" if s.running else (f"{YELLOW}⚠{NC}" if s.installed else f"{RED}✗{NC}")
            opts.append((str(i), f"{ico} {p.meta.name}", f"порт {s.port}" if s.port else "не установлен"))
        opts += [("-", "", ""), ("A", "🔄 Применить конфиг", ""), ("0", "↩ Назад", "")]

        choice = menu(opts, "УПРАВЛЕНИЕ ПРОТОКОЛАМИ")
        if choice == "0":
            return
        elif choice.upper() == "A":
            cfg = generate_config(state, collect_fragments(state))
            if write_config(cfg):
                success("Конфиг применён")
                reload_singbox()
            else:
                error("Ошибка конфига")
            prompt("Нажмите Enter")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(plugins):
                    p = plugins[idx]
                    menu_plugin(state, p)
            except ValueError:
                pass


def menu_plugin(state: AppState, plugin):
    while True:
        clear()
        s = plugin.status()
        proto = state.protocols.get(plugin.meta.name)

        panel(plugin.meta.name.upper(), [
            f"  {DIM}{plugin.meta.description}{NC}",
            "",
            kv("Установлен:", _ok(s.installed)),
            kv("Включён:", _ok(s.enabled)),
            kv("Запущен:", _ok(s.running)),
            kv("Порт:", str(s.port or "—")),
        ])

        choice = menu(
            [
                ("1", "🔧 Установить" if not s.installed else "🔄 Переустановить", ""),
                ("2", "▶️  Включить" if not s.enabled else "⏸️  Выключить", ""),
                ("3", "🗑  Удалить", ""),
                ("0", "↩ Назад", ""),
            ],
            plugin.meta.name.upper(),
        )

        if choice == "0":
            return
        elif choice == "1":
            info(f"Устанавливаю {plugin.meta.name}...")
            if plugin.install():
                success(f"{plugin.meta.name}: OK")
            else:
                error(f"{plugin.meta.name}: ОШИБКА")
            prompt("Нажмите Enter")
        elif choice == "2":
            if not s.enabled:
                if not s.installed:
                    warn("Сначала установите (пункт 1)")
                else:
                    plugin.on_enable(state)
                    if proto:
                        proto.enabled = True
                    save_state(state)
                    success(f"{plugin.meta.name} включён")
            else:
                plugin.on_disable(state)
                if proto:
                    proto.enabled = False
                save_state(state)
                success(f"{plugin.meta.name} выключен")
            prompt("Нажмите Enter")
        elif choice == "3":
            plugin.uninstall()
            if proto:
                proto.enabled = False
                proto.installed = False
            save_state(state)
            success(f"{plugin.meta.name} удалён")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  AWG — специализированное меню
# ═════════════════════════════════════════════════════════════════════════════

def menu_plugin_awg(state: AppState, plugin):
    while True:
        clear()
        s = plugin.status()
        proto = get_protocol(state, "amneziawg")
        config = proto.config
        port = config.get("port", 51820)
        network = config.get("network", "10.8.20.0/24")

        # Трафик и пиры
        traffic = plugin.traffic(state)
        peers = plugin.connected_clients()
        total_bytes = sum(traffic.values())

        if s.installed:
            panel("AWG: AmneziaWG 2.0", [
                kv("Статус:", f"{_ok(s.running)} {'запущен' if s.running else 'остановлен'}"),
                kv("Интерфейс:", f"{YELLOW}awg0{NC}"),
                kv("Порт:", str(port)),
                kv("Сеть:", network),
                kv("Пиров:", f"{len(peers)} онлайн  (всего {sum(1 for u in state.users if not u.blocked)})"),
                kv("Трафик:", _bytes(total_bytes)),
            ])

            opts = [
                ("1", "🗑  Удалить AWG", "Полная очистка: пакеты, модуль, конфиги"),
                ("2", "📄 Клиентский конфиг + QR", ".conf, QR-код, wg:// и sn:// ссылки"),
                ("3", "▶️  Запустить awg0" if not s.running else "⏸️  Остановить awg0", ""),
                ("4", "📊 Статус пиров + трафик",
                 f"{len(peers)} онлайн, {_bytes(total_bytes)}"),
                ("0", "↩ Назад", ""),
            ]
        else:
            panel("AWG: AmneziaWG 2.0", [
                kv("Статус:", f"{RED}не установлен{NC}"),
            ])

            opts = [
                ("1", "🔧 Установить kernel-модуль", "Клонировать wiresock, скомпилировать"),
                ("0", "↩ Назад", ""),
            ]

        choice = menu(opts, "AMNEZIAWG 2.0")

        if choice == "0":
            return
        elif choice == "1":
            if s.installed:
                info("Полное удаление AmneziaWG...")
                plugin.on_disable(state)
                plugin.uninstall()
                subprocess.run(["apt-get", "purge", "-y", "-qq",
                    "amneziawg", "amneziawg-tools", "amneziawg-dkms"], capture_output=True)
                subprocess.run(["modprobe", "-r", "amneziawg"], capture_output=True)
                subprocess.run(["rm", "-rf",
                    "/etc/amnezia/amneziawg",
                    "/usr/bin/awg", "/usr/bin/awg-quick",
                    "/usr/local/bin/awg", "/usr/local/bin/awg-quick",
                    "/opt/awg-install",
                ], capture_output=True)
                if proto:
                    proto.enabled = False
                    proto.installed = False
                save_state(state)
                success("AmneziaWG полностью удалён")
            else:
                info("Устанавливаю AmneziaWG kernel-модуль...")
                if plugin.install():
                    if proto:
                        proto.installed = True
                    save_state(state)
                    success("Установлен. Модуль загружен.")
                else:
                    error("Ошибка установки.")
            prompt("Нажмите Enter")
        elif choice == "2":
            _awg_generate_config(state, plugin)
        elif choice == "3":
            if s.running:
                plugin.on_disable(state)
                if proto:
                    proto.enabled = False
                save_state(state)
                success("awg0 остановлен")
            else:
                if not s.installed:
                    warn("Сначала установите (пункт 1)")
                else:
                    plugin.on_enable(state)
                    if proto:
                        proto.enabled = True
                    save_state(state)
                    success("awg0 запущен")
            prompt("Нажмите Enter")
        elif choice == "4":
            _awg_status_detail(state, plugin)


def _awg_peers_menu(state: AppState, plugin):
    while True:
        clear()
        users = [u for u in state.users if not u.blocked]
    peers = {p["email"]: p for p in plugin.connected_clients()}

    peer_lines = []
    for u in users:
        p = peers.get(u.email)
            ico = f"{GREEN}●{NC}" if (p and p["online"]) else f"{DIM}○{NC}"
            tx = _bytes((p["rx"] + p["tx"]) if p else 0)
            peer_lines.append(f"  {ico} {u.email}")
            peer_lines.append(f"     {DIM}трафик: {tx}{NC}")
        peer_lines += ["", f"  {DIM}● = онлайн  ○ = офлайн{NC}"]
        panel("Пиры AWG", peer_lines)

        choice = menu(
            [("1", "➕ Синхронизировать пиры с пользователями",
              "Добавить всех незаблокированных, убрать заблокированных"),
             ("0", "↩ Назад", "")],
            "УПРАВЛЕНИЕ ПИРАМИ",
        )

        if choice == "0":
            return
        elif choice == "1":
            plugin.configure(state)
            save_state(state)
            success(f"Пиры синхронизированы: {len(users)} активно")
            prompt("Нажмите Enter")


def _awg_generate_config(state: AppState, plugin):
    clear()
    users = [u for u in state.users if not u.blocked]
    if not users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return

    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(users, 1):
        print(f"  {i}. {u.email}")
    print()

    try:
        idx = int(prompt("Номер пользователя", "1")) - 1
    except ValueError:
        warn("Введите число.")
        prompt("Нажмите Enter")
        return
    if not (0 <= idx < len(users)):
        warn("Неверный номер.")
        prompt("Нажмите Enter")
        return

    user = users[idx]
    conf = plugin.generate_client_config(user, state)
    if not conf:
        error("Не удалось сгенерировать конфиг (AWG не настроен?).")
        prompt("Нажмите Enter")
        return

    path = Path(f"/tmp/awg-{user.email}.conf")
    path.write_text(conf)
    wg_link = plugin.client_link(user, state)

    print(f"\n  {GREEN}Конфиг сохранён{NC}")
    print(f"  {DIM}Файл: {path}{NC}")
    print(f"  {CYAN}── .conf{NC}{'─' * 56}")
    print(f"{DIM}{conf}{NC}")
    if wg_link:
        print(f"  {CYAN}── wg://{NC}{'─' * 57}")
        print(f"  {wg_link}")
        try:
            import qrcode
            qr = qrcode.QRCode()
            qr.add_data(wg_link)
            qr.print_ascii()
        except ImportError:
            print(f"  {DIM}pip3 install qrcode — для QR-кода{NC}")
    prompt("Нажмите Enter")


def _awg_status_detail(state: AppState, plugin):
    clear()
    traffic = plugin.traffic(state)
    peers = {p["email"]: p for p in plugin.connected_clients()}

    status_lines = []
    for u in state.users:
        if u.blocked:
            continue
        p = peers.get(u.email)
        ico = f"{GREEN}● онлайн{NC}" if (p and p["online"]) else f"{DIM}○ офлайн{NC}"
        used = traffic.get(u.email, 0)
        status_lines.append(f"  {BOLD}{u.email}{NC}")
        status_lines.append(f"     {ico}  |  {_bytes(used)}")
    panel("Статус пиров", status_lines)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  3. Пользователи
# ═════════════════════════════════════════════════════════════════════════════

def menu_users(state: AppState):
    while True:
        clear()
        traffic = collect_traffic(state)
        total_bytes = sum(traffic.values())
        active = sum(1 for u in state.users if not u.blocked)
        blocked = sum(1 for u in state.users if u.blocked)

        panel("Пользователи", [
            kv("Всего:", str(len(state.users))),
            kv("Активных:", f"{GREEN}{active}{NC}"),
            kv("Заблокировано:", f"{RED}{blocked}{NC}"),
            kv("Трафик всего:", _bytes(total_bytes)),
        ])

        choice = menu(
            [
                ("1", "📋 Список пользователей", f"{len(state.users)} всего, {active} активно"),
                ("2", "➕ Добавить", "Email, лимит, TTL"),
                ("3", "🗑  Удалить", "По email"),
                ("4", "🔒🔓 Заблокировать / Разблокировать", ""),
                ("5", "📊 Лимит трафика", "Установить GB"),
                ("6", "⏰ Срок действия (TTL)", "Дата окончания"),
                ("7", "🔄 Синхронизировать со всеми протоколами",
                 "Обновить пиры в AWG"),
                ("0", "↩ Назад", ""),
            ],
            "ПОЛЬЗОВАТЕЛИ",
        )

        if choice == "0":
            return
        elif choice == "1":
            _show_users(state, traffic)
        elif choice == "2":
            _add_user(state)
        elif choice == "3":
            _delete_user(state)
        elif choice == "4":
            _toggle_block(state)
        elif choice == "5":
            _set_limit(state)
        elif choice == "6":
            _set_ttl(state)
        elif choice == "7":
            _sync_all_protocols(state)


def _show_users(state: AppState, traffic: dict[str, int]):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    title("Список пользователей")
    print()
    for u in state.users:
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        used = traffic.get(u.email, u.traffic_used_bytes)
        limit_bytes = int(u.traffic_limit_gb * 1073741824) if u.traffic_limit_gb else 0
        limit_str = f"{u.traffic_limit_gb} GB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        print(f"  {ico} {BOLD}{u.email}{NC}")
        print(f"     Трафик: {_bytes(used)} / {limit_str}")
        print(f"     {_bar(used, limit_bytes)}")
        print(f"     TTL: {ttl}     UUID: {DIM}{u.uuid[:20]}...{NC}")
        print()
    prompt("Нажмите Enter")


def _add_user(state: AppState):
    email = prompt("Email пользователя")
    if not email:
        return
    if find_user(state, email):
        warn(f"{email} уже существует.")
        prompt("Нажмите Enter")
        return
    limit = prompt("Лимит (GB, 0 = безлимит)", "0")
    ttl = prompt("Срок (дней, 0 = бессрочно)", "0")
    user = User(
        email=email, uuid=str(_uuid.uuid4()),
        traffic_limit_gb=float(limit) if limit else 0,
        expiry_date=("" if int(ttl) <= 0 else datetime.fromtimestamp(
            datetime.now().timestamp() + int(ttl) * 86400).isoformat()),
        created_at=datetime.now().isoformat(),
    )
    orchestrator.add_user(state, user)
    success(f"{email} создан (UUID: {user.uuid[:16]}...)")
    prompt("Нажмите Enter")


def _delete_user(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return

    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        print(f"  {i}. {ico} {u.email}")
    print()

    try:
        idx = int(prompt("Номер для удаления", "0")) - 1
        if 0 <= idx < len(state.users):
            u = state.users[idx]
            orchestrator.remove_user(state, u.email)
            success(f"{u.email} удалён.")
        else:
            warn("Неверный номер.")
    except ValueError:
        warn("Введите число.")
    prompt("Нажмите Enter")


def _toggle_block(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        print(f"  {i}. {ico} {u.email}")
    print()
    try:
        idx = int(prompt("Номер", "0")) - 1
        if 0 <= idx < len(state.users):
            u = state.users[idx]
            if u.blocked:
                orchestrator.unblock_user(state, u.email)
                success(f"{u.email} разблокирован.")
            else:
                orchestrator.block_user(state, u.email)
                success(f"{u.email} заблокирован.")
        else:
            warn("Неверный номер.")
    except ValueError:
        warn("Введите число.")
    prompt("Нажмите Enter")


def _set_limit(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        print(f"  {i}. {u.email}  ({u.traffic_limit_gb or '∞'} GB)")
    print()
    try:
        idx = int(prompt("Номер", "0")) - 1
        if 0 <= idx < len(state.users):
            u = state.users[idx]
            gb = prompt("Лимит (GB, 0 = безлимит)", str(u.traffic_limit_gb))
            u.traffic_limit_gb = float(gb) if gb else 0
            save_state(state)
            success(f"{u.email}: {u.traffic_limit_gb or '∞'} GB")
    except ValueError:
        warn("Введите число.")
    prompt("Нажмите Enter")


def _set_ttl(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        print(f"  {i}. {u.email}  (TTL: {ttl})")
    print()
    try:
        idx = int(prompt("Номер", "0")) - 1
        if 0 <= idx < len(state.users):
            u = state.users[idx]
            days = prompt("Дней от сегодня (0 = бессрочно)", "0")
            u.expiry_date = "" if int(days) <= 0 else datetime.fromtimestamp(
                datetime.now().timestamp() + int(days) * 86400).isoformat()
            save_state(state)
            success(f"{u.email}: TTL {u.expiry_date[:10] if u.expiry_date else '∞'}")
    except ValueError:
        warn("Введите число.")
    prompt("Нажмите Enter")


def _sync_all_protocols(state: AppState):
    """Синхронизирует пользователей со всеми активными протоколами."""
    from hydra.plugins.registry import get_enabled
    info("Синхронизация пиров...")
    for p in get_enabled(state):
        try:
            p.configure(state)
            p.apply(state)
            success(f"  {p.meta.name}: обновлён")
        except Exception as e:
            warn(f"  {p.meta.name}: {e}")
    save_state(state)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  4. Telegram
# ═════════════════════════════════════════════════════════════════════════════

def menu_telegram(state: AppState):
    while True:
        clear()
        tg = state.telegram
        panel("Telegram", [
            kv("Admin токен:", _ok(bool(tg.admin_token))),
            kv("Admin Chat ID:", tg.admin_chat_id or "—"),
            kv("Admin бот:", _ok(tg.admin_enabled)),
            kv("Client токен:", _ok(bool(tg.bot_token))),
            kv("Client бот:", _ok(tg.bot_enabled)),
        ])
        choice = menu(
            [("1", "🔑 Admin-токен", "@BotFather"),
             ("2", "💬 Admin Chat ID", "@userinfobot"),
             ("3", "🤖 Client-токен", "@BotFather"),
             ("4", "▶️  Запустить ботов", "systemd-сервисы"),
             ("5", "⏸️  Остановить ботов", ""),
             ("0", "↩ Назад", "")],
            "TELEGRAM",
        )
        if choice == "0":
            return
        elif choice == "1":
            t = prompt("Токен admin-бота")
            if t:
                state.telegram.admin_token = t
                save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "2":
            c = prompt("Admin Chat ID (число)")
            if c:
                state.telegram.admin_chat_id = c
                save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "3":
            t = prompt("Токен клиентского бота")
            if t:
                state.telegram.bot_token = t
                save_state(state)
                success("Сохранён")
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
        error("Сначала укажите admin-токен")
        prompt("Нажмите Enter")
        return
    install_service("hydra-tg-admin", f"""[Unit]
Description=HYDRA Admin Bot
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_admin_bot; run_admin_bot('{state.telegram.admin_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
""")
    state.telegram.admin_enabled = True
    success("Admin-бот запущен (hydra-tg-admin)")
    if state.telegram.bot_token:
        install_service("hydra-tg-bot", f"""[Unit]
Description=HYDRA Client Bot
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_client_bot; run_client_bot('{state.telegram.bot_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
""")
        state.telegram.bot_enabled = True
        success("Client-бот запущен (hydra-tg-bot)")
    save_state(state)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  5. Мониторинг
# ═════════════════════════════════════════════════════════════════════════════

def menu_monitoring(state: AppState):
    while True:
        clear()
        traffic = collect_traffic(state)
        total = sum(traffic.values())
        panel("Мониторинг", [
            kv("Трафик всего:", _bytes(total)),
            kv("Пользователей:", str(len(state.users))),
        ])
        choice = menu(
            [("1", "📊 Трафик по пользователям", ""),
             ("2", "🔌 Статус протоколов", ""),
             ("3", "🔄 Sync Agent", "systemd timer, каждые 5 мин"),
             ("0", "↩ Назад", "")],
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
    title("Трафик")
    print()
    for u in state.users:
        used = traffic.get(u.email, u.traffic_used_bytes)
        lim = int(u.traffic_limit_gb * 1073741824) if u.traffic_limit_gb else 0
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        print(f"  {ico} {BOLD}{u.email}{NC}")
        print(f"     {_bytes(used)} / {u.traffic_limit_gb or '∞'} GB")
        print(f"     {_bar(used, lim)}")
        print()
    prompt("Нажмите Enter")


def _show_status():
    clear()
    title("Статус протоколов")
    print()
    for name, s in status_all().items():
        ico = f"{GREEN}●{NC}" if s["running"] else (f"{YELLOW}●{NC}" if s["installed"] else f"{DIM}●{NC}")
        port = f":{s['port']}" if s["port"] else ""
        print(f"  {ico} {name:<14} порт{port:<6} {'запущен' if s['running'] else 'стоп'}")
    print()
    prompt("Нажмите Enter")


def _install_sync_agent(state: AppState):
    install_timer("hydra-sync-agent",
        """[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -m hydra.services.sync_agent
""",
        """[Unit]
Description=HYDRA Sync Agent Timer
[Timer]
OnCalendar=*:0/5
Persistent=true
[Install]
WantedBy=timers.target
""")
    success("Sync Agent установлен (каждые 5 мин)")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  6. Безопасность
# ═════════════════════════════════════════════════════════════════════════════

def menu_security(state: AppState):
    while True:
        clear()
        sec = state.security
        panel("Безопасность", [
            kv("GeoIP:", f"{_ok(sec.geoip_block_enabled)}  (РФ, порт {sec.geoip_port})"),
            kv("Fail2ban:", _ok(sec.fail2ban_enabled)),
            kv("Honeypot:", _ok(sec.honeypot_enabled)),
        ])
        choice = menu(
            [("1", f"🌍 GeoIP  [{_ok(sec.geoip_block_enabled)}]", "iptables + ipset"),
             ("2", f"🛡️  Fail2ban  [{_ok(sec.fail2ban_enabled)}]", ""),
             ("3", f"🪤 Honeypot  [{_ok(sec.honeypot_enabled)}]", ""),
             ("0", "↩ Назад", "")],
            "БЕЗОПАСНОСТЬ",
        )
        if choice == "0":
            return
        elif choice == "1":
            sec.geoip_block_enabled = not sec.geoip_block_enabled
            save_state(state)
            success(f"GeoIP {'включен' if sec.geoip_block_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "2":
            sec.fail2ban_enabled = not sec.fail2ban_enabled
            save_state(state)
            success(f"Fail2ban {'включён' if sec.fail2ban_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "3":
            sec.honeypot_enabled = not sec.honeypot_enabled
            save_state(state)
            success(f"Honeypot {'включён' if sec.honeypot_enabled else 'выключен'}")
            prompt("Нажмите Enter")
