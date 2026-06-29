"""
hydra/ui/menus.py — Главное меню и подменю HYDRA v2.

Архитектура:
  • main_menu — корень, 7 разделов (ядро, протоколы, пользователи, Telegram,
    мониторинг, безопасность, VPS)
  • Раздел «Протоколы» разбит на категории: TRANSPORT, ENHANCEMENT, SECURITY
  • Раздел «Пользователи» содержит детальный просмотр + ссылки/конфиги
  • Раздел «Безопасность» — полноценное управление, а не просто toggle
  • Раздел «Мониторинг» — система, трафик, логи
"""
from __future__ import annotations

import subprocess
import sys
import uuid as _uuid
from datetime import datetime
from pathlib import Path

from hydra.core.state import (
    AppState, User, save_state, find_user, get_protocol,
)
from hydra.core.singbox import (
    install as install_singbox,
    generate_config, write_config, reload as reload_singbox,
    start as start_singbox, is_running,
    is_installed as singbox_installed, get_version as singbox_version,
)
from hydra.plugins.registry import (
    enabled, collect_fragments,
    status_all, transports, enhancements, security as sec_plugins,
)
from hydra.plugins.base import PluginCategory
from hydra.core.systemd import install_service, install_timer, remove_unit
from hydra.core import orchestrator
from hydra.services.subscriptions.generator import start_sub_server
from hydra.services.traffic import collect_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC,
    PANEL_W,
)

_sub_server = None


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════

def _sys_info() -> list[str]:
    """Возвращает строки с информацией о системе."""
    lines = []
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot
        d, r = divmod(int(uptime.total_seconds()), 86400)
        h, m = divmod(r, 3600)
        m, _ = divmod(m, 60)
        lines.append(kv("CPU:", f"{cpu:.0f}%"))
        lines.append(kv("RAM:", f"{mem.percent:.0f}%  ({_bytes_auto(mem.used)} / {_bytes_auto(mem.total)})"))
        lines.append(kv("Диск:", f"{disk.percent:.0f}%  ({_bytes_auto(disk.used)} / {_bytes_auto(disk.total)})"))
        lines.append(kv("Uptime:", f"{d}д {h:02d}:{m:02d}"))
    except ImportError:
        lines.append(kv("PSUTIL:", f"{YELLOW}не установлен{NC}"))
    except Exception:
        pass
    return lines


def _select_user(state: AppState, prompt_text: str = "") -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    if not state.users:
        warn("Нет пользователей.")
        return None

    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        used = _bytes_auto(u.traffic_used_bytes)
        lim = f"{u.traffic_limit_gb} GB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        print(f"  {i}. {ico} {BOLD}{u.email:<24}{NC}  {used} / {lim}  TTL: {ttl}")
    print()

    try:
        idx = int(prompt(prompt_text or "Номер пользователя", "1")) - 1
    except ValueError:
        warn("Введите число.")
        return None
    if not (0 <= idx < len(state.users)):
        warn("Неверный номер.")
        return None
    return state.users[idx]


def _show_user_detail(state: AppState, user: User):
    """Детальная информация о пользователе + ссылки."""
    clear()
    traffic = collect_traffic(state)
    used = traffic.get(user.email, user.traffic_used_bytes)
    lim = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    ico = f"{RED}🔴{NC}" if user.blocked else f"{GREEN}🟢{NC}"

    protos = []
    for p in enabled(state):
        link = ""
        try:
            link = p.client_link(user, state) or ""
        except Exception:
            pass
        protos.append(f"  {p.meta.name:<14} {GREEN}{p.status().port or '—'}{NC}  {DIM}{link[:50]}{NC}")

    panel(f"Пользователь {user.email}", [
        kv("Статус:", f"{'ЗАБЛОКИРОВАН' if user.blocked else 'АКТИВЕН'}"),
        kv("UUID:", user.uuid),
        kv("Трафик:", f"{_bytes_auto(used)} / {user.traffic_limit_gb or '∞'} GB"),
        *([kv("Прогресс:", _bar(used, lim))] if user.traffic_limit_gb else []),
        kv("TTL:", user.expiry_date[:10] if user.expiry_date else "∞"),
        kv("Создан:", user.created_at[:10] if user.created_at else "—"),
        kv("Telegram ID:", str(user.telegram_id or "—")),
        "",
        f"  {BOLD}Протоколы:{NC}",
        *protos,
    ])
    prompt("Нажмите Enter")


def _user_links(state: AppState, user: User):
    """Показывает ссылки и конфиги пользователя для всех протоколов."""
    clear()
    print(f"\n  {CYAN}Конфиги и ссылки для {BOLD}{user.email}{NC}\n")

    for p in enabled(state, PluginCategory.TRANSPORT):
        conf = ""
        link = ""
        try:
            conf = p.generate_client_config(user, state) or ""
        except Exception:
            pass
        try:
            link = p.client_link(user, state) or ""
        except Exception:
            pass
        if not conf and not link:
            continue
        print(f"  {CYAN}── {BOLD}{p.meta.name}{NC}{CYAN}{'─' * (PANEL_W - 10 - len(p.meta.name))}{NC}")
        if link:
            print(f"  {GREEN}Ссылка:{NC}  {link}")
            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(link)
                qr.print_ascii()
            except ImportError:
                pass
        if conf:
            print(f"  {DIM}{conf[:PANEL_W]}{NC}")
            if len(conf) > PANEL_W:
                print(f"  {DIM}... ({len(conf)} всего символов){NC}")
        print()

    sub_url = f"http://{state.network.server_ip or 'SERVER_IP'}:8443/?token={user.uuid}&format=base64"
    print(f"  {CYAN}── Подписка (Base64){'─' * (PANEL_W - 22)}{NC}")
    print(f"  {DIM}{sub_url}{NC}")
    print()
    prompt("Нажмите Enter")


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

        lines = [
            kv("Sing-Box:", f"{_ok(sb_ok)}  {singbox_version() or 'не установлен'}"),
            kv("Протоколов:", f"{GREEN}{active_p}{NC}/{total_p} запущено"),
            kv("Пользователей:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ]
        lines += _sys_info()
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "⚙️  Ядро и система",     f"Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"NaiveProxy, Mieru, AmneziaWG, DNSCrypt, WARP  [{active_p}/{total_p}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       f"Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          f"Трафик, статус, sync-агент, логи"),
                ("6", "🛡️  Безопасность",       f"GeoIP, fail2ban, honeypot, IPBan"),
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
#  2. Протоколы — разбиты по категориям
# ═════════════════════════════════════════════════════════════════════════════

def menu_protocols(state: AppState):
    while True:
        clear()
        st = status_all()

        transport_lines = []
        for p in transports():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            port = f":{s['port']}" if s.get("port") else ""
            st_txt = "вкл" if s.get("enabled") else "выкл"
            transport_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st_txt:>4}{NC}  порт{port}")

        enhancement_lines = []
        for p in enhancements():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            port = f":{s['port']}" if s.get("port") else ""
            enhancement_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{'вкл' if s.get('enabled') else 'выкл':>4}{NC}  порт{port}")

        security_p_lines = []
        for p in sec_plugins():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            security_p_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{'вкл' if s.get('enabled') else 'выкл':>4}{NC}")

        lines = [
            f"  {BOLD}Транспорты:{NC}",
            *transport_lines,
            "",
            f"  {BOLD}Улучшения:{NC}",
            *enhancement_lines,
        ]
        if security_p_lines:
            lines += ["", f"  {BOLD}Безопасность:{NC}", *security_p_lines]
        panel("Протоколы", lines)

        all_p = transports() + enhancements() + sec_plugins()
        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(all_p, 1):
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}✓{NC}" if s.get("running") else (f"{YELLOW}⚠{NC}" if s.get("installed") else f"{RED}✗{NC}")
            opts.append((str(i),
                         f"{ico} {p.meta.name}",
                         f"порт {s['port']}" if s.get("port") else "не установлен"))
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
                if 0 <= idx < len(all_p):
                    p = all_p[idx]
                    if p.meta.name == "amneziawg":
                        menu_plugin_awg(state, p)
                    else:
                        menu_plugin(state, p)
            except ValueError:
                pass


def menu_plugin(state: AppState, plugin):
    while True:
        clear()
        s = plugin.status()

        panel(plugin.meta.name.upper(), [
            f"  {DIM}{plugin.meta.description}{NC}",
            "",
            kv("Категория:", plugin.meta.category.value),
            kv("Версия:", plugin.meta.version),
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
                    proto = get_protocol(state, plugin.meta.name)
                    if proto:
                        proto.enabled = True
                    save_state(state)
                    success(f"{plugin.meta.name} включён")
            else:
                plugin.on_disable(state)
                proto = get_protocol(state, plugin.meta.name)
                if proto:
                    proto.enabled = False
                save_state(state)
                success(f"{plugin.meta.name} выключен")
            prompt("Нажмите Enter")
        elif choice == "3":
            plugin.uninstall()
            proto = get_protocol(state, plugin.meta.name)
            if proto:
                proto.enabled = False
                proto.installed = False
            save_state(state)
            success(f"{plugin.meta.name} удалён")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  AWG — специализированное меню (самый сложный протокол)
# ═════════════════════════════════════════════════════════════════════════════

def menu_plugin_awg(state: AppState, plugin):
    while True:
        clear()
        s = plugin.status()
        proto = get_protocol(state, "amneziawg")
        config = proto.config
        port = config.get("port", 51820)
        network = config.get("network", "10.8.20.0/24")

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
                kv("Трафик:", _bytes_auto(total_bytes)),
            ])

            opts = [
                ("1", "🗑  Удалить AWG", "Полная очистка: пакеты, модуль, конфиги"),
                ("2", "📄 Клиентский конфиг + QR", ".conf, QR-код, wg:// и sn:// ссылки"),
                ("3", "▶️  Запустить awg0" if not s.running else "⏸️  Остановить awg0", ""),
                ("4", "📊 Статус пиров + трафик",
                 f"{len(peers)} онлайн, {_bytes_auto(total_bytes)}"),
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
            tx = _bytes_auto((p["rx"] + p["tx"]) if p else 0)
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
    user = _select_user(state, "Номер пользователя для конфига")
    if not user:
        prompt("Нажмите Enter")
        return

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
        status_lines.append(f"     {ico}  |  {_bytes_auto(used)}")
    panel("Статус пиров", status_lines)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  3. Пользователи — полностью переработано
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
            kv("Трафик всего:", _bytes_auto(total_bytes)),
        ])

        choice = menu(
            [
                ("1", "📋 Список пользователей", f"{len(state.users)} всего, {active} активно"),
                ("2", "👤 Детально / Конфиги",  "Выбрать пользователя: трафик, TTL, ссылки, QR"),
                ("3", "➕ Добавить",            "Email, лимит, TTL"),
                ("4", "🗑  Удалить",            "По email"),
                ("5", "🔒🔓 Заблокировать / Разблокировать", ""),
                ("6", "📊 Лимит трафика",       "Установить GB"),
                ("7", "⏰ Срок действия (TTL)",  "Дата окончания"),
                ("8", "🔄 Синхронизировать",    "Обновить пиры во всех протоколах"),
                ("0", "↩ Назад", ""),
            ],
            "ПОЛЬЗОВАТЕЛИ",
        )

        if choice == "0":
            return
        elif choice == "1":
            _show_users(state, traffic)
        elif choice == "2":
            user = _select_user(state, "Номер пользователя")
            if user:
                _user_detail_menu(state, user)
        elif choice == "3":
            _add_user(state)
        elif choice == "4":
            _delete_user(state)
        elif choice == "5":
            _toggle_block(state)
        elif choice == "6":
            _set_limit(state)
        elif choice == "7":
            _set_ttl(state)
        elif choice == "8":
            _sync_all_protocols(state)


def _user_detail_menu(state: AppState, user: User):
    """Подменю для одного выбранного пользователя."""
    while True:
        clear()
        traffic = collect_traffic(state)
        used = traffic.get(user.email, user.traffic_used_bytes)
        lim = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
        ico = f"{RED}🔴{NC}" if user.blocked else f"{GREEN}🟢{NC}"

        panel(f"👤 {user.email}", [
            kv("Статус:", f"{'ЗАБЛОКИРОВАН' if user.blocked else 'АКТИВЕН'}"),
            kv("UUID:", f"{DIM}{user.uuid}{NC}"),
            kv("Трафик:", f"{_bytes_auto(used)} / {user.traffic_limit_gb or '∞'} GB"),
            *([kv("Прогресс:", _bar(used, lim))] if user.traffic_limit_gb else []),
            kv("TTL:", user.expiry_date[:10] if user.expiry_date else "∞"),
            kv("Создан:", user.created_at[:10] if user.created_at else "—"),
            kv("Telegram ID:", str(user.telegram_id or "—")),
            kv("Подписка:", f"{DIM}{state.network.server_ip or 'SERVER_IP'}:8443?token={user.uuid[:8]}...{NC}"),
        ])

        choice = menu(
            [
                ("1", "📄 Показать ссылки / конфиги", "Все протоколы, QR, подписка"),
                ("2", "🔒 Заблокировать" if not user.blocked else "🔓 Разблокировать", ""),
                ("3", "📊 Изменить лимит", f"Сейчас: {user.traffic_limit_gb or '∞'} GB"),
                ("4", "⏰ Изменить TTL", f"Сейчас: {user.expiry_date[:10] if user.expiry_date else '∞'}"),
                ("5", "🗑  Удалить", ""),
                ("0", "↩ Назад", ""),
            ],
            f"ПОЛЬЗОВАТЕЛЬ {user.email}",
        )

        if choice == "0":
            return
        elif choice == "1":
            _user_links(state, user)
        elif choice == "2":
            if user.blocked:
                orchestrator.unblock_user(state, user.email)
                success(f"{user.email} разблокирован")
            else:
                orchestrator.block_user(state, user.email)
                success(f"{user.email} заблокирован")
            prompt("Нажмите Enter")
        elif choice == "3":
            gb = prompt("Лимит (GB, 0 = безлимит)", str(user.traffic_limit_gb))
            user.traffic_limit_gb = float(gb) if gb else 0
            save_state(state)
            success(f"{user.email}: {user.traffic_limit_gb or '∞'} GB")
            prompt("Нажмите Enter")
        elif choice == "4":
            days = prompt("Дней от сегодня (0 = бессрочно)", "0")
            if days:
                user.expiry_date = "" if int(days) <= 0 else datetime.fromtimestamp(
                    datetime.now().timestamp() + int(days) * 86400).isoformat()
                save_state(state)
                ttl = user.expiry_date[:10] if user.expiry_date else "∞"
                success(f"{user.email}: TTL {ttl}")
            prompt("Нажмите Enter")
        elif choice == "5":
            if confirm(f"Удалить {user.email}?", default=False):
                orchestrator.remove_user(state, user.email)
                success(f"{user.email} удалён")
            prompt("Нажмите Enter")
            return


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
        print(f"     Трафик: {_bytes_auto(used)} / {limit_str}")
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
    user = _select_user(state, "Номер для удаления")
    if not user:
        prompt("Нажмите Enter")
        return
    if confirm(f"Удалить {user.email}?", default=False):
        orchestrator.remove_user(state, user.email)
        success(f"{user.email} удалён.")
    prompt("Нажмите Enter")


def _toggle_block(state: AppState):
    clear()
    user = _select_user(state, "Номер")
    if not user:
        prompt("Нажмите Enter")
        return
    if user.blocked:
        orchestrator.unblock_user(state, user.email)
        success(f"{user.email} разблокирован.")
    else:
        orchestrator.block_user(state, user.email)
        success(f"{user.email} заблокирован.")
    prompt("Нажмите Enter")


def _set_limit(state: AppState):
    clear()
    user = _select_user(state, "Номер")
    if not user:
        prompt("Нажмите Enter")
        return
    gb = prompt("Лимит (GB, 0 = безлимит)", str(user.traffic_limit_gb))
    user.traffic_limit_gb = float(gb) if gb else 0
    save_state(state)
    success(f"{user.email}: {user.traffic_limit_gb or '∞'} GB")
    prompt("Нажмите Enter")


def _set_ttl(state: AppState):
    clear()
    user = _select_user(state, "Номер")
    if not user:
        prompt("Нажмите Enter")
        return
    days = prompt("Дней от сегодня (0 = бессрочно)", "0")
    if days:
        user.expiry_date = "" if int(days) <= 0 else datetime.fromtimestamp(
            datetime.now().timestamp() + int(days) * 86400).isoformat()
        save_state(state)
        ttl = user.expiry_date[:10] if user.expiry_date else "∞"
        success(f"{user.email}: TTL {ttl}")
    prompt("Нажмите Enter")


def _sync_all_protocols(state: AppState):
    """Синхронизирует пользователей со всеми активными протоколами."""
    info("Синхронизация пиров...")
    for p in enabled(state):
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
            kv("Admin бот:", f"{_ok(tg.admin_enabled)} {'запущен' if tg.admin_enabled else 'остановлен'}"),
            kv("Client токен:", _ok(bool(tg.bot_token))),
            kv("Client бот:", f"{_ok(tg.bot_enabled)} {'запущен' if tg.bot_enabled else 'остановлен'}"),
        ])
        choice = menu(
            [("1", "🔑 Admin-токен", "@BotFather"),
             ("2", "💬 Admin Chat ID", "@userinfobot"),
             ("3", "🤖 Client-токен", "@BotFather"),
             ("4", "▶️  Запустить admin-бота", "systemd-сервис hydra-tg-admin"),
             ("5", "▶️  Запустить client-бота", "systemd-сервис hydra-tg-bot"),
             ("6", "⏸️  Остановить всех ботов", ""),
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
            _install_admin_bot(state)
        elif choice == "5":
            _install_client_bot(state)
        elif choice == "6":
            remove_unit("hydra-tg-admin")
            remove_unit("hydra-tg-bot")
            state.telegram.admin_enabled = False
            state.telegram.bot_enabled = False
            save_state(state)
            success("Боты остановлены")
            prompt("Нажмите Enter")


def _install_admin_bot(state: AppState):
    if not state.telegram.admin_token:
        error("Сначала укажите admin-токен (пункт 1)")
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
    save_state(state)
    success("Admin-бот запущен (hydra-tg-admin)")
    prompt("Нажмите Enter")


def _install_client_bot(state: AppState):
    if not state.telegram.bot_token:
        error("Сначала укажите client-токен (пункт 3)")
        prompt("Нажмите Enter")
        return
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
    save_state(state)
    success("Client-бот запущен (hydra-tg-bot)")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  5. Мониторинг
# ═════════════════════════════════════════════════════════════════════════════

def menu_monitoring(state: AppState):
    while True:
        clear()
        traffic = collect_traffic(state)
        total = sum(traffic.values())
        lines = [
            kv("Трафик всего:", _bytes_auto(total)),
            kv("Пользователей:", str(len(state.users))),
        ]
        lines += _sys_info()
        panel("Мониторинг", lines)

        choice = menu(
            [("1", "📊 Трафик по пользователям", ""),
             ("2", "🔌 Статус протоколов", ""),
             ("3", "📋 Лог Sing-Box", "tail -20 /var/log/sing-box/sing-box.log"),
             ("4", "🔄 Sync Agent", "systemd timer, каждые 5 мин"),
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
            _show_singbox_log()
        elif choice == "4":
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
        print(f"     {_bytes_auto(used)} / {u.traffic_limit_gb or '∞'} GB")
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


def _show_singbox_log():
    clear()
    title("Лог Sing-Box (последние 30 строк)")
    print()
    try:
        log = Path("/var/log/sing-box/sing-box.log")
        if log.exists():
            lines = log.read_text(encoding="utf-8").strip().split("\n")
            for line in lines[-30:]:
                print(f"  {DIM}{line}{NC}")
        else:
            warn("Лог-файл не найден")
    except Exception as e:
        error(f"Ошибка чтения лога: {e}")
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
#  6. Безопасность — полноценное меню
# ═════════════════════════════════════════════════════════════════════════════

def menu_security(state: AppState):
    while True:
        clear()
        sec = state.security
        st = status_all()

        panel("Безопасность", [
            kv("GeoIP:", f"{_ok(sec.geoip_block_enabled)}  (РФ, порт {sec.geoip_port})"),
            kv("Fail2ban:", _ok(sec.fail2ban_enabled)),
            kv("Honeypot:", _ok(sec.honeypot_enabled)),
            kv("IPBan:", _ok(st.get("ipban", {}).get("enabled", False))),
        ])

        choice = menu(
            [
                ("1", f"🌍 GeoIP         [{_ok(sec.geoip_block_enabled)}]", "Блокировка РФ по ipset"),
                ("2", f"🛡️  Fail2ban     [{_ok(sec.fail2ban_enabled)}]", "Защита от брутфорса"),
                ("3", f"🪤 Honeypot      [{_ok(sec.honeypot_enabled)}]", "Ловушка для сканеров"),
                ("4", f"🚫 IPBan         [{_ok(st.get('ipban', {}).get('enabled', False))}]", "Блокировка по IP"),
                ("-", "", ""),
                ("A", "✅ Включить всё", "GeoIP + Fail2ban + Honeypot + IPBan"),
                ("B", "❌ Выключить всё", ""),
                ("0", "↩ Назад", ""),
            ],
            "БЕЗОПАСНОСТЬ",
        )

        if choice == "0":
            return
        elif choice == "1":
            sec.geoip_block_enabled = not sec.geoip_block_enabled
            save_state(state)
            _toggle_security_plugin(state, "geoip")
            success(f"GeoIP {'включён' if sec.geoip_block_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "2":
            sec.fail2ban_enabled = not sec.fail2ban_enabled
            save_state(state)
            _toggle_security_plugin(state, "fail2ban")
            success(f"Fail2ban {'включён' if sec.fail2ban_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "3":
            sec.honeypot_enabled = not sec.honeypot_enabled
            save_state(state)
            _toggle_security_plugin(state, "honeypot")
            success(f"Honeypot {'включён' if sec.honeypot_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "4":
            _toggle_security_plugin(state, "ipban")
            success("IPBan переключён")
            prompt("Нажмите Enter")
        elif choice.upper() == "A":
            sec.geoip_block_enabled = True
            sec.fail2ban_enabled = True
            sec.honeypot_enabled = True
            save_state(state)
            for name in ("geoip", "fail2ban", "honeypot", "ipban"):
                _toggle_security_plugin(state, name, force_enable=True)
            success("Всё включено")
            prompt("Нажмите Enter")
        elif choice.upper() == "B":
            sec.geoip_block_enabled = False
            sec.fail2ban_enabled = False
            sec.honeypot_enabled = False
            save_state(state)
            for name in ("geoip", "fail2ban", "honeypot", "ipban"):
                _toggle_security_plugin(state, name, force_enable=False)
            success("Всё выключено")
            prompt("Нажмите Enter")


def _toggle_security_plugin(state: AppState, name: str, force_enable: bool | None = None):
    """Включает/выключает security-плагин через его on_enable/on_disable."""
    from hydra.plugins.registry import get as get_plugin
    p = get_plugin(name)
    if not p:
        return

    proto = get_protocol(state, name)
    if force_enable is True:
        p.on_enable(state)
        if proto:
            proto.enabled = True
    elif force_enable is False:
        p.on_disable(state)
        if proto:
            proto.enabled = False
    else:
        # toggle
        if proto and proto.enabled:
            p.on_disable(state)
            proto.enabled = False
        else:
            p.on_enable(state)
            if proto:
                proto.enabled = True
    save_state(state)
