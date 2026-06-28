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
    AppState, User, load_state, save_state, find_user, add_user,
)
from hydra.core.singbox import (
    install as install_singbox,
    generate_config, write_config, reload as reload_singbox,
    start as start_singbox, is_running, status_text,
    is_installed as singbox_installed, get_version as singbox_version,
)
from hydra.plugins.registry import (
    get_all, get as get_plugin, get_enabled, collect_fragments,
    status_all,
)
from hydra.plugins.base import ConfigFragment
from hydra.core.systemd import install_service, install_timer, remove_unit
from hydra.services.subscriptions.generator import start_sub_server
from hydra.services.traffic import collect_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt,
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

        print(f"  {CYAN}┌── Состояние{NC}{'─' * 48}{NC}")
        print(f"  {CYAN}│{NC}  Sing-Box:    {_ok(sb_ok)}  {singbox_version() or 'не установлен'}")
        print(f"  {CYAN}│{NC}  Протоколов:  {GREEN}{active_p}{NC}/{total_p} запущено")
        print(f"  {CYAN}│{NC}  Пользователей: {GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()

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
            print(f"\n{GREEN}До свидания!{NC}")
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

        print(f"\n  {CYAN}┌── Sing-Box{NC}{'─' * 48}{NC}")
        print(f"  {CYAN}│{NC}  Статус:   {_ok(ok_r)} {'запущен' if ok_r else 'остановлен'}")
        print(f"  {CYAN}│{NC}  Версия:   {ver or '—'}")
        print(f"  {CYAN}│{NC}  Конфиг:   /etc/sing-box/config.json")
        print(f"  {CYAN}│{NC}  Лог:      /var/log/sing-box/sing-box.log")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()

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
            frag_dicts = {}
            for n, f in collect_fragments(state).items():
                frag_dicts[n] = {"inbounds": f.inbounds, "outbounds": f.outbounds, "route_rules": f.route_rules}
            cfg = generate_config(state, frag_dicts)
            if write_config(cfg):
                success("Конфиг записан")
                (success if reload_singbox() else warn)("Sing-Box перезагружен" if reload_singbox() else "Перезагрузка не удалась")
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

        print(f"\n  {CYAN}┌── Протоколы{NC}{'─' * 48}{NC}")
        for p in plugins:
            s = p.status()
            ico = f"{GREEN}●{NC}" if s.running else (f"{YELLOW}●{NC}" if s.installed else f"{DIM}●{NC}")
            port = f":{s.port}" if s.port else ""
            st = "вкл" if s.enabled else "выкл"
            print(f"  {CYAN}│{NC}  {ico} {p.meta.name:<14} {DIM}{st:>4}{NC}  порт{port}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()

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
            fd = {n: {"inbounds": f.inbounds, "outbounds": f.outbounds, "route_rules": f.route_rules}
                  for n, f in collect_fragments(state).items()}
            cfg = generate_config(state, fd)
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
        proto = state.protocols.get(plugin.meta.name)

        print(f"\n  {CYAN}╔══ {plugin.meta.name.upper()} {NC}{'═' * (40 - len(plugin.meta.name))}{NC}")
        print(f"  {CYAN}║{NC}  {plugin.meta.description}")
        print(f"  {CYAN}║{NC}")
        print(f"  {CYAN}║{NC}  Установлен: {_ok(s.installed)}")
        print(f"  {CYAN}║{NC}  Включён:    {_ok(s.enabled)}")
        print(f"  {CYAN}║{NC}  Запущен:    {_ok(s.running)}")
        print(f"  {CYAN}║{NC}  Порт:       {s.port or '—'}")
        print(f"  {CYAN}╚{'═' * 54}{NC}")
        print()

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
            (success if plugin.install() else error)(f"{plugin.meta.name}: {'OK' if plugin.install() else 'ОШИБКА'}")
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
        proto = state.protocols.get("amneziawg")
        config = proto.config if proto else {}
        port = config.get("port", 51820)
        network = config.get("network", "10.8.20.0/24")

        # Трафик и пиры
        traffic = plugin.traffic()
        peers = plugin.connected_peers()
        total_bytes = sum(traffic.values())

        if s.installed:
            print(f"\n  {CYAN}┌── AWG: AmneziaWG 2.0{NC}{'─' * 38}{NC}")
            print(f"  {CYAN}│{NC}  Статус:      {_ok(s.running)} {'запущен' if s.running else 'остановлен'}")
            print(f"  {CYAN}│{NC}  Интерфейс:   {YELLOW}awg0{NC}")
            print(f"  {CYAN}│{NC}  Порт:        {port}")
            print(f"  {CYAN}│{NC}  Сеть:        {network}")
            print(f"  {CYAN}│{NC}  Пиров:       {len(peers)} онлайн  (всего {sum(1 for u in state.users if not u.blocked)})")
            print(f"  {CYAN}│{NC}  Трафик:      {_bytes(total_bytes)}")
            print(f"  {CYAN}└{'─' * 54}{NC}")
            print()

            opts = [
                ("1", "🗑  Удалить AWG", "Полная очистка: пакеты, модуль, конфиги"),
                ("2", "📄 Клиентский конфиг + QR", ".conf, QR-код, wg:// и sn:// ссылки"),
                ("3", "▶️  Запустить awg0" if not s.running else "⏸️  Остановить awg0", ""),
                ("4", "📊 Статус пиров + трафик",
                 f"{len(peers)} онлайн, {_bytes(total_bytes)}"),
                ("0", "↩ Назад", ""),
            ]
        else:
            print(f"\n  {CYAN}┌── AWG: AmneziaWG 2.0{NC}{'─' * 38}{NC}")
            print(f"  {CYAN}│{NC}  Статус:      {RED}не установлен{NC}")
            print(f"  {CYAN}└{'─' * 54}{NC}")
            print()

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
        peers = plugin.connected_peers()
        peer_keys = {p["pubkey"]: p for p in peers}

        print(f"\n  {CYAN}┌── Пиры AWG{NC}{'─' * 47}{NC}")
        for u in users:
            pubkey = _derive_awg_pubkey(u.uuid)
            online = "●" if pubkey in peer_keys else "○"
            ico = f"{GREEN}{online}{NC}"
            traffic_bytes = peer_keys[pubkey].get("transfer", "0 B") if pubkey in peer_keys else "0 B"
            print(f"  {CYAN}│{NC}  {ico} {u.email}")
            print(f"  {CYAN}│{NC}     трафик: {traffic_bytes}")
        print(f"  {CYAN}│{NC}")
        print(f"  {CYAN}│{NC}  ● = онлайн  ○ = офлайн")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()

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
            if plugin.status().running:
                plugin._down()
                plugin._up()
            save_state(state)
            success(f"Пиры синхронизированы: {len(users)} добавлено")
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
        if 0 <= idx < len(users):
            user = users[idx]
            conf = plugin.generate_client_config(user, state)
            path = Path(f"/tmp/awg-{user.email}.conf")
            path.write_text(conf)

            import re
            priv = re.search(r"PrivateKey\s*=\s*(\S+)", conf)
            pub = re.search(r"PublicKey\s*=\s*(\S+)", conf)
            ep = re.search(r"Endpoint\s*=\s*(\S+)", conf)
            addr = re.search(r"Address\s*=\s*(\S+)", conf)
            jc = re.search(r"Jc\s*=\s*(\S+)", conf)
            jmin = re.search(r"Jmin\s*=\s*(\S+)", conf)
            jmax = re.search(r"Jmax\s*=\s*(\S+)", conf)
            s1 = re.search(r"S1\s*=\s*(\S+)", conf)
            s2 = re.search(r"S2\s*=\s*(\S+)", conf)
            h1 = re.search(r"H1\s*=\s*(\S+)", conf)
            h2 = re.search(r"H2\s*=\s*(\S+)", conf)
            h3 = re.search(r"H3\s*=\s*(\S+)", conf)
            h4 = re.search(r"H4\s*=\s*(\S+)", conf)

            if priv and pub and ep:
                ip, port = ep.group(1).split(":") if ":" in ep.group(1) else (ep.group(1), "51820")
                params = []
                if priv: params.append(f"private_key={priv.group(1)}")
                if addr: params.append(f"local_address={addr.group(1)}")
                params.append("enable_amnezia=true")
                if jc: params.append(f"jc={jc.group(1)}")
                if jmin: params.append(f"jmin={jmin.group(1)}")
                if jmax: params.append(f"jmax={jmax.group(1)}")
                if s1: params.append(f"s1={s1.group(1)}")
                if s2: params.append(f"s2={s2.group(1)}")
                if h1: params.append(f"h1={h1.group(1)}")
                if h2: params.append(f"h2={h2.group(1)}")
                if h3: params.append(f"h3={h3.group(1)}")
                if h4: params.append(f"h4={h4.group(1)}")
                if pub: params.append(f"public_key={pub.group(1)}")
                params.append("persistent_keepalive_interval=25")
                wg_link = f"wg://{ip}:{port}?{'&'.join(params)}#{user.email}%20AWG"

                import base64
                sn_link = f"sn://awg?{base64.urlsafe_b64encode(conf.encode()).decode()}"

                print(f"\n  {GREEN}Конфиг сохранён{NC}")
                print(f"  {DIM}Файл: {path}{NC}")
                print(f"  {CYAN}── wg://{NC}{'─' * 57}")
                print(f"  {wg_link}")
                print(f"  {CYAN}── sn://{NC}{'─' * 57}")
                print(f"  {sn_link}")

                try:
                    import qrcode
                    qr = qrcode.QRCode()
                    qr.add_data(wg_link)
                    qr.print_ascii()
                except ImportError:
                    print(f"  {DIM}pip3 install qrcode — для QR{NC}")
            else:
                success(f"Конфиг сохранён: {path}")
                print(f"\n{DIM}{conf[:400]}{NC}\n")
        else:
            warn("Неверный номер.")
    except ValueError:
        warn("Введите число.")
    prompt("Нажмите Enter")


def _awg_status_detail(state: AppState, plugin):
    clear()
    traffic = plugin.traffic()
    peers = plugin.connected_peers()
    users = state.users

    print(f"\n  {CYAN}┌── Статус пиров{NC}{'─' * 46}{NC}")
    for u in users:
        if u.blocked:
            continue
        pubkey = _derive_awg_pubkey(u.uuid)
        online = pubkey in {p["pubkey"] for p in peers}
        ico = f"{GREEN}● онлайн{NC}" if online else f"{DIM}○ офлайн{NC}"
        used = traffic.get(pubkey, 0)
        print(f"  {CYAN}│{NC}  {u.email}")
        print(f"  {CYAN}│{NC}     {ico}  |  {_bytes(used)}")
    print(f"  {CYAN}└{'─' * 54}{NC}")
    print()
    prompt("Нажмите Enter")


def _derive_awg_pubkey(uuid: str) -> str:
    import hashlib, base64
    h = hashlib.sha256(uuid.encode()).digest()
    private = base64.b64encode(h[:32]).decode()
    import subprocess
    r = subprocess.run(
        ["awg", "pubkey"], input=private,
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


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

        print(f"\n  {CYAN}┌── Пользователи{NC}{'─' * 45}{NC}")
        print(f"  {CYAN}│{NC}  Всего:          {len(state.users)}")
        print(f"  {CYAN}│{NC}  Активных:       {GREEN}{active}{NC}")
        print(f"  {CYAN}│{NC}  Заблокировано:  {RED}{blocked}{NC}")
        print(f"  {CYAN}│{NC}  Трафик всего:   {_bytes(total_bytes)}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()

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
    print(f"\n{BOLD}{CYAN}  Список пользователей:{NC}\n")
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
    add_user(state, user)
    save_state(state)
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
            state.users.remove(u)
            save_state(state)
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
            u.blocked = not u.blocked
            save_state(state)
            success(f"{u.email} {'заблокирован' if u.blocked else 'разблокирован'}.")
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
        print(f"\n  {CYAN}┌── Telegram{NC}{'─' * 50}{NC}")
        print(f"  {CYAN}│{NC}  Admin токен:  {_ok(bool(tg.admin_token))}")
        print(f"  {CYAN}│{NC}  Admin Chat ID: {tg.admin_chat_id or '—'}")
        print(f"  {CYAN}│{NC}  Admin бот:    {_ok(tg.admin_enabled)}")
        print(f"  {CYAN}│{NC}  Client токен: {_ok(bool(tg.bot_token))}")
        print(f"  {CYAN}│{NC}  Client бот:   {_ok(tg.bot_enabled)}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()
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
        print(f"\n  {CYAN}┌── Мониторинг{NC}{'─' * 47}{NC}")
        print(f"  {CYAN}│{NC}  Трафик всего: {_bytes(total)}")
        print(f"  {CYAN}│{NC}  Пользователей: {len(state.users)}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()
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
    print(f"\n{BOLD}{CYAN}  Трафик:{NC}\n")
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
    print(f"\n{BOLD}{CYAN}  Статус протоколов:{NC}\n")
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
        print(f"\n  {CYAN}┌── Безопасность{NC}{'─' * 46}{NC}")
        print(f"  {CYAN}│{NC}  GeoIP:        {_ok(sec.geoip_block_enabled)}  (РФ, порт {sec.geoip_port})")
        print(f"  {CYAN}│{NC}  Fail2ban:     {_ok(sec.fail2ban_enabled)}")
        print(f"  {CYAN}│{NC}  Honeypot:     {_ok(sec.honeypot_enabled)}")
        print(f"  {CYAN}└{'─' * 54}{NC}")
        print()
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
