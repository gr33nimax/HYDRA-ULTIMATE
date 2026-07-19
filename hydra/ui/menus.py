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

from hydra.core.host import HOST

import subprocess  # legacy test/import surface; command execution uses HostBackend/log_viewer
import sys
import uuid as _uuid
import math
import re
from datetime import datetime
from pathlib import Path

from hydra.core.state import (
    AppState, User, PluginState, save_state, load_state, update_state, find_user, get_protocol,
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
from hydra.services.subscriptions.generator import (
    get_subscription_urls, get_user_access_status,
    get_user_entitlement_status,
)
from hydra.services.traffic import (
    collect_traffic, update_user_traffic, refresh_traffic_state, protocol_totals,
)
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC,
    PANEL_W,
)
from hydra.ui.protocol_ui import (
    protocol_label, protocol_menu_title, protocol_status_panel, status_badge,
)
from hydra.ui.protocol_menu import (
    enhancement_options, enhancement_summary_lines, menu_footer,
    render_protocol_status, transport_options, transport_summary_lines,
)
from hydra.ui.network_info import snapshot as network_snapshot
from hydra.ui import log_viewer, system_monitor
from hydra.services.application import ApplicationService, production_application


def _application(app: ApplicationService | None = None) -> ApplicationService:
    """Resolve explicit menu dependencies while keeping legacy calls working."""
    return app or production_application()


def _apply_error_text(default: str = "Ошибка применения конфигурации") -> str:
    """Prefer the concrete error reported by the orchestrator."""
    return orchestrator.last_apply_error() or default



# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════

import os


def _sys_info(state: AppState | None = None) -> list[str]:
    """Возвращает строки с информацией о системе и сети."""
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
        # Резервный сбор метрик через стандартную библиотеку и /proc (на Linux)
        try:
            import shutil
            
            # 1. Диск через shutil (стандартная библиотека)
            total_d, used_d, free_d = shutil.disk_usage("/")
            disk_pct = (used_d / total_d) * 100 if total_d > 0 else 0
            
            # 2. Метрики для Unix-систем
            uptime_str = "—"
            load_str = "—"
            mem_str = "—"
            
            if os.name != "nt":
                # Uptime из /proc/uptime
                uptime_file = Path("/proc/uptime")
                if uptime_file.exists():
                    with open(uptime_file, "r") as f:
                        uptime_sec = float(f.readline().split()[0])
                    d, r = divmod(int(uptime_sec), 86400)
                    h, m = divmod(r, 3600)
                    m, _ = divmod(m, 60)
                    uptime_str = f"{d}д {h:02d}:{m:02d}"
                
                # Средняя нагрузка (Load Average)
                avg1, avg5, _ = os.getloadavg()
                load_str = f"{avg1:.2f}, {avg5:.2f}"
                
                # RAM из /proc/meminfo
                meminfo_file = Path("/proc/meminfo")
                if meminfo_file.exists():
                    meminfo = {}
                    with open(meminfo_file, "r") as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 2:
                                meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024
                    m_total = meminfo.get("MemTotal", 0)
                    m_free = meminfo.get("MemFree", 0)
                    m_buffers = meminfo.get("Buffers", 0)
                    m_cached = meminfo.get("Cached", 0)
                    m_used = m_total - m_free - m_buffers - m_cached
                    m_pct = (m_used / m_total) * 100 if m_total > 0 else 0
                    mem_str = f"{m_pct:.0f}%  ({_bytes_auto(m_used)} / {_bytes_auto(m_total)})"
            
            if load_str != "—":
                lines.append(kv("Load Avg:", load_str))
            if mem_str != "—":
                lines.append(kv("RAM:", mem_str))
            lines.append(kv("Диск:", f"{disk_pct:.0f}%  ({_bytes_auto(used_d)} / {_bytes_auto(total_d)})"))
            if uptime_str != "—":
                lines.append(kv("Uptime:", uptime_str))
        except Exception:
            pass
    except Exception:
        pass
        
    # Добавление сетевой информации (асинхронно, без фризов интерфейса)
    try:
        from hydra.utils.net import local_ip
        loc = local_ip()
        
        # Получаем внешний IP (берем из кэша, если пуст — пробуем AppState)
        network = network_snapshot()
        pub_ip = network.public_ip
        if pub_ip == "Получение..." and state and state.network.server_ip:
            pub_ip = state.network.server_ip
            
        flag_suffix = f" {network.country_flag}" if network.country_flag else ""
        # Если публичный и локальный совпадают (нет NAT), выводим один IP для красоты
        if pub_ip == loc:
            lines.append(kv("IP (Public):", f"{CYAN}{pub_ip}{NC}{flag_suffix}"))
        else:
            lines.append(kv("IP (Pub/Loc):", f"{CYAN}{pub_ip}{NC}{flag_suffix} / {DIM}{loc}{NC}"))
            
        dns_display = network.dns
        try:
            import subprocess
            import re
            r = HOST.run(["systemctl", "is-active", "dnscrypt-proxy"], capture_output=True, text=True, timeout=1)
            if r.stdout.strip() == "active":
                conf_path = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
                if conf_path.exists():
                    content = conf_path.read_text(encoding="utf-8")
                    m = re.search(r"^server_names\s*=\s*\[(.*?)\]", content, flags=re.MULTILINE | re.DOTALL)
                    if m:
                        names_str = m.group(1)
                        names = [n.strip("'\" ") for n in names_str.split(",") if n.strip("'\" ")]
                        if names:
                            dns_display = f"{GREEN}DNSCrypt ({', '.join(names)}){NC}"
                        else:
                            dns_display = f"{GREEN}DNSCrypt (весь пул){NC}"
                    else:
                        dns_display = f"{GREEN}DNSCrypt (активен){NC}"
                else:
                    dns_display = f"{GREEN}DNSCrypt (активен){NC}"
        except Exception:
            pass

        lines.append(kv("DNS:", dns_display))
    except Exception:
        pass

    return lines


def _select_user(state: AppState, prompt_text: str = "") -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    if not state.users:
        warn("Нет пользователей.")
        return None

    update_user_traffic(state)
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        available, reason = get_user_access_status(u)
        ico = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        used = _bytes_auto(u.traffic_used_bytes)
        lim = f"{u.traffic_limit_gb:g} GiB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        state_text = "" if available else f"  {RED}{reason}{NC}"
        print(f"  {i}. {ico} {BOLD}{u.email:<24}{NC}  {used} / {lim}  до {ttl}{state_text}")
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
    """Monitoring-only user statistics without secrets or client links."""
    clear()
    update_user_traffic(state)
    used = user.traffic_used_bytes
    lim = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    status = f"{RED}заблокирован 🔴{NC}" if user.blocked else f"{GREEN}активен 🟢{NC}"
    expiry = user.expiry_date[:10] if user.expiry_date else "бессрочно"
    if user.expiry_date:
        try:
            expiry_dt = datetime.fromisoformat(user.expiry_date)
            remaining = (expiry_dt - datetime.now(expiry_dt.tzinfo)).days
            expiry = f"{expiry} · {'истёк' if remaining < 0 else f'{remaining} дн.'}"
        except (TypeError, ValueError):
            pass

    summary = [
        kv("Статус:", status),
        kv("Трафик:", f"{BOLD}{_bytes_auto(used)}{NC}"),
        kv("Лимит:", f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "без ограничений"),
        *([kv("Прогресс:", _bar(used, lim))] if user.traffic_limit_gb else []),
        kv("Подписка:", expiry),
        kv("Создан:", user.created_at[:10] if user.created_at else "—"),
    ]
    panel(f"👤 {user.email}", summary)

    enabled_names = {
        plugin.meta.name for plugin in enabled(state, PluginCategory.TRANSPORT)
        if plugin.meta.name != "wdtt"
    }
    labels = {
        "amneziawg": "AmneziaWG", "naive": "NaiveProxy",
        "anytls": "AnyTLS", "mieru": "Mieru",
        "trusttunnel": "TrustTunnel", "shadowtls": "ShadowTLS",
        "hysteria2": "Hysteria2", "snell": "Snell",
        "telemt": "Telemt",
    }
    order = [
        "amneziawg", "naive", "anytls", "mieru", "trusttunnel",
        "shadowtls", "hysteria2", "snell", "telemt",
    ]
    protocol_values = {
        name: max(0, int(stats.get("traffic_used_bytes", 0)))
        for name, stats in user.credentials.items()
        if isinstance(stats, dict)
    }
    names = [name for name in order if name in enabled_names or protocol_values.get(name, 0)]
    names.extend(sorted(set(protocol_values) - set(names) - {"wdtt"}))
    attributed = sum(protocol_values.get(name, 0) for name in names)

    print()
    print(f"  {BOLD}Трафик по протоколам{NC}")
    print(f"  {BOLD}{'Протокол':<18} {'Накоплено':>14} {'Доля':>9}{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    for name in names:
        value = protocol_values.get(name, 0)
        share = value / used * 100 if used else 0
        print(f"  {labels.get(name, name):<18} {_bytes_auto(value):>14} {share:>8.1f}%")
    legacy = max(0, used - attributed)
    if legacy:
        share = legacy / used * 100 if used else 0
        print(f"  {'Без разбивки':<18} {_bytes_auto(legacy):>14} {share:>8.1f}%")
    if not names and not legacy:
        print(f"  {DIM}Пользователь пока не расходовал трафик.{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    print(f"  {DIM}qWDTT здесь не отображается: для него доступен только общий счётчик.{NC}")
    print()
    prompt("Нажмите Enter")


def _user_links(state: AppState, user: User):
    """Показывает ссылки и конфиги пользователя для всех протоколов."""
    clear()
    print(f"\n  {CYAN}Конфиги и ссылки для {BOLD}{user.email}{NC}\n")

    for p in enabled(state, PluginCategory.TRANSPORT):
        if p.meta.name == "amneziawg":
            ps = state.protocols.get("amneziawg")
            has_mobile = ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]
            profiles = ["desktop"]
            if has_mobile:
                profiles.append("mobile")
            
            for prof in profiles:
                conf = ""
                link = ""
                vpn_link = ""
                try:
                    conf = p.generate_client_config(user, state, profile=prof) or ""
                except Exception:
                    pass
                try:
                    link = p.client_link(user, state, profile=prof) or ""
                except Exception:
                    pass
                try:
                    vpn_link = p.amnezia_link(user, state, profile=prof) or ""
                except Exception:
                    pass
                if not conf and not link and not vpn_link:
                    continue
                label_ru = "ПК / Desktop" if prof == "desktop" else "Смартфон / Mobile"
                print(f"  {CYAN}── {BOLD}{p.meta.name.upper()} ({label_ru}){NC}{CYAN}{'─' * (PANEL_W - 14 - len(p.meta.name) - len(label_ru))}{NC}")
                if link:
                    print(f"  {GREEN}Ссылка (WireGuard):{NC}  {link}")
                if conf:
                    try:
                        import qrcode
                        qr = qrcode.QRCode()
                        qr.add_data(conf)
                        qr.print_ascii()
                    except Exception:
                        pass
                if conf:
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                    for line in conf.splitlines():
                        print(f"  {DIM}{line}{NC}")
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                print()
            continue

        conf = ""
        links = []
        try:
            conf = p.generate_client_config(user, state) or ""
        except Exception:
            pass
        try:
            if hasattr(p, "client_links"):
                links = p.client_links(user, state)
            else:
                l = p.client_link(user, state)
                if l:
                    links = [l]
        except Exception:
            pass
        if not conf and not links:
            continue
        print(f"  {CYAN}── {BOLD}{p.meta.name}{NC}{CYAN}{'─' * (PANEL_W - 10 - len(p.meta.name))}{NC}")
        if links:
            for l in links:
                print(f"  {GREEN}Ссылка:{NC}  {l}")
        if conf:
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
            for line in conf.splitlines():
                print(f"  {DIM}{line}{NC}")
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
        print()

    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню
# ═════════════════════════════════════════════════════════════════════════════

def main_menu(state: AppState, app: ApplicationService | None = None):
    app = _application(app)
    while True:
        clear()
        print(BANNER)

        sb_ok = singbox_installed() and is_running()
        plugins = status_all()

        active_t = sum(1 for p in transports() if plugins.get(p.meta.name, {}).get("running"))
        total_t = len(transports())

        active_e = sum(1 for p in enhancements() if plugins.get(p.meta.name, {}).get("running"))
        total_e = len(enhancements())

        active_s = sum(1 for p in sec_plugins() if plugins.get(p.meta.name, {}).get("running"))
        total_s = len(sec_plugins())

        u_active = sum(1 for u in state.users if get_user_access_status(u)[0])

        lines = [
            kv("Sing-Box:", f"{_ok(sb_ok)}  {singbox_version() or 'не установлен'}"),
            kv("Протоколы:", f"{GREEN}{active_t}{NC}/{total_t} активны"),
            kv("Сетевые службы:", f"{GREEN}{active_e}{NC}/{total_e} активны"),
            kv("Безопасность:", f"{GREEN}{active_s}{NC}/{total_s} активны"),
            kv("Пользователи:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ]
        lines += _sys_info(state)
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "📦 Ядро и система",       "Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"Транспорты (Naive, AmneziaWG, Mieru...)  [{active_t}/{total_t}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       "Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          "Трафик, статус, sync-агент, логи"),
                ("6", "🔒 Безопасность",        f"Fail2ban, Honeypot, IPBan  [{active_s}/{total_s}]"),
                ("7", "🌐 Сетевые службы",      f"DNSCrypt, WARP (DNS и маршрутизация)  [{active_e}/{total_e}]"),
                ("8", "🛠️  Тестирование и отладка", "Проверка скорости, блокировок, GeoIP и CPU"),
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
            menu_protocols(state, app)
        elif choice == "3":
            menu_users(state, app)
        elif choice == "4":
            menu_telegram(state)
        elif choice == "5":
            menu_monitoring(state)
        elif choice == "6":
            menu_security(state)
        elif choice == "7":
            menu_network_services(state, app)
        elif choice == "8":
            from hydra.ui.diagnostics import menu_diagnostics
            menu_diagnostics(state)


# ═════════════════════════════════════════════════════════════════════════════
#  1. Ядро и система
# ═════════════════════════════════════════════════════════════════════════════

def menu_core(state: AppState):
    while True:
        state = load_state()
        clear()
        ok_i = singbox_installed()
        ok_r = is_running()
        ver = singbox_version()

        update_available = state.install.get("singbox_update_available", False)
        latest_version = state.install.get("singbox_latest_version", "")

        ver_text = ver or "—"
        if ok_i and update_available:
            ver_text += f" {YELLOW}(Доступно обновление){NC}"

        panel("Sing-Box", [
            kv("Статус:", f"{_ok(ok_r)} {'запущен' if ok_r else 'остановлен'}"),
            kv("Версия:", ver_text),
            kv("Конфиг:", f"{DIM}/etc/sing-box/config.json{NC}"),
            kv("Лог:", f"{DIM}journalctl -u sing-box{NC}"),
        ])

        menu_items = [
            ("1", "📦 Установить Sing-Box Extended" if not ok_i else "🔄 Переустановить",
             "shtorm-7/sing-box-extended"),
            ("2", "▶️  Запустить" if not ok_r else "⏸️  Остановить", ""),
            ("3", "🔄 Применить конфиг",
             "Собрать /etc/sing-box/config.json и перезагрузить"),
            ("4", "🚀 Оптимизировать сеть", "BBR/FQ, TCP/UDP-буферы и очереди в один клик"),
            ("5", "↩️  Откатить оптимизацию сети", "Восстановить параметры до первого применения"),
        ]

        if ok_i:
            if update_available:
                menu_items.append(("6", "🆙 Установить обновление", f"Доступна версия sing-box-extended {latest_version}"))
            else:
                menu_items.append(("X", "🆙 Установить обновления", "Установлена последняя версия sing-box-extended"))

        menu_items.append(("0", "↩ Назад", ""))

        choice = menu(menu_items, "ЯДРО И СИСТЕМА")

        if choice == "0":
            return
        elif choice == "1":
            info("Устанавливаю Sing-Box...")
            if install_singbox(force=ok_i):
                success(f"Sing-Box {singbox_version()} установлен")
                if orchestrator.apply_config(state):
                    success("Конфигурация пересобрана и применена")
                else:
                    warn(_apply_error_text("Не удалось автоматически применить конфигурацию"))
            else:
                error("Не удалось установить")
            prompt("Нажмите Enter")
        elif choice == "6" and ok_i and update_available:
            info("Устанавливаю обновление Sing-Box...")
            from hydra.core.singbox import update_kernel
            ok, msg = update_kernel()
            if ok:
                success(msg)
                if orchestrator.apply_config(state):
                    success("Конфигурация пересобрана и применена")
                else:
                    warn(_apply_error_text("Не удалось автоматически применить конфигурацию"))
            else:
                error(msg)
            prompt("Нажмите Enter")
        elif choice == "X" and ok_i and not update_available:
            continue
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
            info("Пересобираю конфиг...")
            if orchestrator.apply_config(state):
                success("Конфиг применён, Sing-Box перезагружен")
            else:
                error(_apply_error_text("Ошибка применения конфигурации"))
            prompt("Нажмите Enter")
        elif choice == "4":
            _apply_network_tuning_menu()
        elif choice == "5":
            _rollback_network_tuning_menu()


def _apply_network_tuning_menu() -> None:
    from hydra.core.network_tuning import apply_network_tuning

    if not confirm(
        "Применить оптимальный сетевой профиль HYDRA? Текущие значения будут сохранены",
        default=True,
    ):
        return
    info("Настраиваю сетевой стек VPS...")
    try:
        report = apply_network_tuning()
    except Exception as exc:
        error(f"Не удалось применить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    changed = sum(1 for item in report["sysctl"].values() if item.get("changed"))
    skipped = sum(1 for item in report["sysctl"].values() if item.get("skipped"))
    lines = [
        f"  Изменено параметров: {GREEN}{changed}{NC}",
        f"  BBR: {_ok(report['bbr_available'])}",
        f"  Постоянный профиль: {DIM}{report['config_path']}{NC}",
    ]
    if skipped:
        lines.append(f"  Не поддерживается ядром: {YELLOW}{skipped}{NC}")
    for message in report["errors"][:5]:
        lines.append(f"  {RED}{message}{NC}")
    panel("Сетевая оптимизация", lines)
    if report["success"]:
        success("Сетевой профиль применён. Перезагрузка не требуется")
    else:
        warn("Профиль применён частично; подробности показаны выше")
    prompt("Нажмите Enter")


def _rollback_network_tuning_menu() -> None:
    from hydra.core.network_tuning import rollback_network_tuning

    if not confirm("Восстановить сетевые параметры до оптимизации?", default=False):
        return
    try:
        report = rollback_network_tuning()
    except Exception as exc:
        error(f"Не удалось откатить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    if report["success"]:
        success(f"Восстановлено параметров: {report['restored']}")
    else:
        error("Не удалось полностью откатить сетевой профиль")
        for message in report["errors"]:
            warn(message)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  2. Протоколы — разбиты по категориям
# ═════════════════════════════════════════════════════════════════════════════

def menu_protocols(state: AppState, app: ApplicationService | None = None):
    app = _application(app)
    while True:
        clear()
        st = app.protocols.statuses(state)
        all_p = app.protocols.list(PluginCategory.TRANSPORT)

        transport_lines = transport_summary_lines(all_p, st)

        lines = [
            f"  {BOLD}Транспортные протоколы{NC}",
            *transport_lines,
        ]
        panel("Протоколы · обзор", lines)

        opts = transport_options(all_p, st) + menu_footer()

        choice = menu(opts, "ПРОТОКОЛЫ · УПРАВЛЕНИЕ")
        if choice == "0":
            return
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_p):
                    p = all_p[idx]
                    menu_plugin(state, p, app)
            except ValueError:
                pass


def menu_network_services(state: AppState, app: ApplicationService | None = None):
    app = _application(app)
    while True:
        clear()
        st = app.protocols.statuses(state)
        all_p = app.protocols.list(PluginCategory.ENHANCEMENT)

        enhancement_lines = enhancement_summary_lines(all_p, st)

        lines = [
            f"  {BOLD}Сетевые службы (DNS / Маршрутизация):{NC}",
            *enhancement_lines,
        ]
        panel("Сетевые службы", lines)

        opts = enhancement_options(all_p, st) + menu_footer()

        choice = menu(opts, "СЕТЕВЫЕ СЛУЖБЫ")
        if choice == "0":
            return
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_p):
                    p = all_p[idx]
                    menu_plugin(state, p, app)
            except ValueError:
                pass


def menu_plugin(state: AppState, p, app: ApplicationService | None = None):
    app = _application(app)
    """Универсальное меню плагина."""
    if p.meta.name == "amneziawg":
        _menu_amneziawg(state, p)
        return
    if p.meta.name == "anytls":
        _menu_anytls(state, p)
        return
    if p.meta.name == "mieru":
        _menu_mieru(state, p)
        return
    if p.meta.name == "trusttunnel":
        _menu_trusttunnel(state, p)
        return
    if p.meta.name == "dnscrypt":
        from hydra.plugins.dnscrypt.manager import menu_dnscrypt
        menu_dnscrypt(state, p)
        return
    if p.meta.name == "fail2ban":
        from hydra.plugins.fail2ban.manager import menu_fail2ban
        menu_fail2ban(state, p)
        return
    if p.meta.name == "ipban":
        from hydra.plugins.ipban.manager import menu_ipban
        menu_ipban(state, p)
        return
    if p.meta.name == "honeypot":
        from hydra.plugins.honeypot.manager import menu_honeypot
        menu_honeypot(state, p)
        return
    if p.meta.name == "warp":
        from hydra.plugins.warp.manager import menu_warp
        menu_warp(state, p)
        return
    if p.meta.name == "telemt":
        from hydra.plugins.telemt.manager import menu_telemt
        menu_telemt(state, p)
        return
    if p.meta.name == "wdtt":
        from hydra.plugins.wdtt.manager import menu_wdtt
        menu_wdtt(state, p)
        return

    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Единая карточка статуса для протоколов без собственного менеджера.
        render_protocol_status(p, ps)
        
        # Опции зависят от состояния
        options = []
        
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            # Для TRANSPORT-плагинов: показать подключённых клиентов
            if p.meta.category == PluginCategory.TRANSPORT and ps.enabled:
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
            
            # Для NaiveProxy — пункт смены транспорта
            if p.meta.name == "naive" and ps.enabled:
                current_net = ps.config.get("network", "tcp") if ps.config else "tcp"
                net_label = {"tcp": "HTTP/2", "quic": "QUIC", "both": "HTTP/2+QUIC"}.get(current_net, current_net)
                options.append(("3", "🔀 Сменить транспорт", f"Текущий: {net_label}"))

            if p.meta.name == "shadowtls":
                current_sni = ps.config.get("handshake_sni", "не выбран") if ps.config else "не выбран"
                options.append(("3", "🌐 Сменить SNI", f"Текущий: {current_sni}"))

            if p.meta.name in {"hysteria2", "snell"}:
                options.append(("3", "⚙️  Настройки", "Параметры транспорта и обфускации"))

            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = app.protocols.install(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if app.protocols.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text())
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if app.protocols.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text())
            else:
                try:
                    if app.protocols.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text())
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
        
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
        
        elif choice == "3" and p.meta.name == "naive" and ps.enabled:
            mode_choice = menu([
                ("1", "HTTP/2 (TCP)", "Стандартный режим, максимальная совместимость"),
                ("2", "QUIC (UDP)", "HTTP/3 через UDP, может быть быстрее"),
                ("3", "HTTP/2 + QUIC", "Оба транспорта одновременно"),
                ("0", "↩ Отмена", ""),
            ], header="Транспорт NaiveProxy")
            if mode_choice != "0":
                mode_map = {"1": "tcp", "2": "quic", "3": "both"}
                new_mode = mode_map.get(mode_choice)
                if new_mode:
                    if p.set_transport(state, new_mode):
                        success(f"Транспорт изменён на {new_mode}")
                    else:
                        error(
                            "Не удалось применить транспорт. Возможно, UDP/443 уже "
                            "занят TrustTunnel QUIC; прежний режим восстановлен."
                        )
                    prompt("Нажмите Enter")

        elif choice == "3" and p.meta.name == "shadowtls" and ps.installed:
            new_sni = p.choose_handshake_sni()
            if new_sni:
                try:
                    if p.set_handshake_sni(state, new_sni):
                        success(f"SNI ShadowTLS изменён на {new_sni}")
                    else:
                        error("Не удалось применить SNI; прежняя конфигурация восстановлена")
                except ValueError as exc:
                    error(str(exc))
            prompt("Нажмите Enter")

        elif choice == "3" and p.meta.name == "hysteria2" and ps.installed:
            _menu_hysteria2_settings(state, p)

        elif choice == "3" and p.meta.name == "snell" and ps.installed:
            _menu_snell_settings(state, p)

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = app.protocols.reinstall(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка переустановки")
                prompt("Нажмите Enter")
        
        elif choice == "9" and ps.installed:
            if confirm(f"Удалить {p.meta.name}?", default=False):
                app.protocols.uninstall(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return
        
        elif choice == "0":
            return


def _menu_hysteria2_settings(state: AppState, plugin) -> None:
    """Runtime-safe Hysteria2 settings editor."""
    from hydra.core.state import get_protocol
    from hydra.utils.crypto import gen_token

    while True:
        ps = get_protocol(state, "hysteria2")
        mode = ps.config.get("congestion_mode", "bbr")
        bandwidth = ""
        if mode == "brutal":
            bandwidth = f" · {ps.config.get('up_mbps', 100)}/{ps.config.get('down_mbps', 100)} Mbps"
        choice = menu([
            ("1", "🌐 Домен и TLS", ps.config.get("domain", "не задан")),
            ("2", "🔌 UDP-порт", str(ps.config.get("port", 8443))),
            ("3", "🚀 Congestion control", f"{str(mode).upper()}{bandwidth}"),
            ("4", "🔑 Сменить Salamander-пароль", "Клиентские ссылки обновятся"),
            ("0", "↩ Назад", ""),
        ], "НАСТРОЙКИ HYSTERIA2")
        if choice == "0":
            return
        try:
            if choice == "1":
                domain = prompt("Новый домен Hysteria2", default=ps.config.get("domain", ""))
                if domain and plugin.set_domain(state, domain):
                    success("Домен и TLS-сертификат обновлены")
                elif domain:
                    error("Не удалось применить домен; прежняя конфигурация восстановлена")
            elif choice == "2":
                value = prompt("Новый UDP-порт", default=str(ps.config.get("port", 8443)))
                if plugin.set_port(state, int(value)):
                    success("UDP-порт обновлён")
                else:
                    error("Не удалось применить порт; прежняя конфигурация восстановлена")
            elif choice == "3":
                selected = menu([
                    ("1", "BBR", "Автоматическая оценка пропускной способности"),
                    ("2", "Brutal", "Явно заданные upload/download Mbps"),
                    ("0", "Отмена", ""),
                ], "CONGESTION CONTROL HYSTERIA2")
                if selected == "1":
                    ok = plugin.set_congestion(state, "bbr")
                elif selected == "2":
                    up = int(prompt("Upload Mbps", default=str(ps.config.get("up_mbps", 100))))
                    down = int(prompt("Download Mbps", default=str(ps.config.get("down_mbps", 100))))
                    ok = plugin.set_congestion(state, "brutal", up, down)
                else:
                    continue
                success("Congestion control обновлён") if ok else error(
                    "Не удалось применить режим; прежняя конфигурация восстановлена"
                )
            elif choice == "4":
                value = prompt(
                    "Новый пароль (пусто = сгенерировать)", default="",
                ).strip() or gen_token(24)
                if plugin.set_obfs_password(state, value):
                    success("Salamander-пароль обновлён")
                else:
                    error("Не удалось сменить пароль; прежняя конфигурация восстановлена")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _menu_snell_settings(state: AppState, plugin) -> None:
    """Runtime-safe Snell simple-obfs editor."""
    from hydra.core.state import get_protocol

    while True:
        ps = get_protocol(state, "snell")
        version = plugin._version(state)
        mode = str(ps.config.get("obfs_mode", "http"))
        host = str(ps.config.get("obfs_host", "www.bing.com"))
        choice = menu([
            ("1", "🎭 Simple obfs", f"{mode.upper()} · {host}" if mode else "выключен"),
            ("0", "↩ Назад", ""),
        ], f"НАСТРОЙКИ SNELL v{version}")
        if choice == "0":
            return
        try:
            if choice == "1":
                selected = menu([
                    ("1", "HTTP obfs", "Имитация HTTP-трафика"),
                    ("2", "Выключить", "Чистый Snell без simple-obfs"),
                    ("0", "Отмена", ""),
                ], "SIMPLE OBFS SNELL")
                new_mode = {"1": "http", "2": ""}.get(selected)
                if new_mode is None:
                    continue
                new_host = host
                if new_mode:
                    new_host = prompt("Маскировочный host", default=host)
                ok = plugin.set_settings(state, version, new_mode, new_host)
            else:
                continue
            success("Настройки Snell обновлены") if ok else error(
                "Не удалось применить настройки; прежняя конфигурация восстановлена"
            )
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _show_plugin_clients(state: AppState, p):
    """Показывает подключённых клиентов и трафик для протокола с двойными рамками."""
    clear()
    
    try:
        # Безопасно проверяем, поддерживает ли метод connected_clients передачу state
        import inspect
        sig = inspect.signature(p.connected_clients)
        if "state" in sig.parameters or len(sig.parameters) > 0:
            clients = p.connected_clients(state)
        else:
            clients = p.connected_clients()
            
        traffic = p.traffic(state)
        
        box_lines = []
        
        # Сводные показатели
        total_clients = len(clients) if clients else len(traffic) if traffic else 0
        online_clients = sum(1 for c in clients if c.get("online")) if clients else 0
        total_rx = sum(c.get("rx", 0) for c in clients) if clients else 0
        total_tx = sum(c.get("tx", 0) for c in clients) if clients else 0
        
        if not clients and not traffic:
            box_lines.append(f"{YELLOW}Нет активных клиентов или трафика{NC}")
        else:
            if clients:
                box_lines.append(f"{BOLD}{WHITE}Активные сессии:{NC}")
                now_ts = int(datetime.now().timestamp())
                for c in clients:
                    status = f"{GREEN}🟢{NC}" if c.get("online") else f"{RED}🔴{NC}"
                    email = c.get("email", "?")
                    rx = _bytes_auto(c.get("rx", 0))
                    tx = _bytes_auto(c.get("tx", 0))
                    
                    # Форматируем время последнего хендшейка
                    handshake = c.get("last_handshake", 0)
                    if handshake == 0:
                        activity = f"{DIM}не активен{NC}"
                    else:
                        diff = now_ts - handshake
                        if diff < 10:
                            activity = f"{GREEN}активен{NC}"
                        elif diff < 60:
                            activity = f"{GREEN}только что{NC}"
                        elif diff < 3600:
                            activity = f"{GREEN}{diff // 60} мин. назад{NC}"
                        elif diff < 86400:
                            activity = f"{DIM}{diff // 3600} ч. назад{NC}"
                        else:
                            activity = f"{DIM}{diff // 86400} дн. назад{NC}"
                            
                    box_lines.append(f"  {status} {BOLD}{email:<18}{NC}  ↓{rx:<9} ↑{tx:<9}  {activity}")
            elif traffic:
                box_lines.append(f"{BOLD}{WHITE}Статистика трафика:{NC}")
                for email, bytes_total in traffic.items():
                    box_lines.append(f"  {BOLD}{email:<20}{NC}  {_bytes_auto(bytes_total)}")
            
            # Добавляем сводный блок трафика
            box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
            box_lines.append(f"{BOLD}{WHITE}СВОДНАЯ СТАТИСТИКА ПОТОКА:{NC}")
            box_lines.append(f"  Всего клиентов:  {total_clients}")
            if clients:
                box_lines.append(f"  В сети (online): {GREEN}{online_clients}{NC}")
                box_lines.append(f"  Получено (RX):   {GREEN}{_bytes_auto(total_rx)}{NC}")
                box_lines.append(f"  Отправлено (TX): {GREEN}{_bytes_auto(total_tx)}{NC}")
                box_lines.append(f"  Общий трафик:    {CYAN}{_bytes_auto(total_rx + total_tx)}{NC}")
                
        panel(f"👥  КЛИЕНТЫ: {p.meta.name.upper()}", box_lines)
    except Exception as e:
        error(f"Ошибка получения клиентов: {e}")
    
    print()
    prompt("Нажмите Enter")





# ═════════════════════════════════════════════════════════════════════════════
#  3. Пользователи — полностью переработано
# ═════════════════════════════════════════════════════════════════════════════

def menu_users(state: AppState, app: ApplicationService | None = None):
    app = _application(app)
    """Управление пользователями."""
    while True:
        clear()
        title("Пользователи")
        
        # Показать краткую сводку
        total = len(state.users)
        active = sum(1 for u in state.users if get_user_access_status(u)[0])
        restricted = total - active
        info(f"Всего: {total}  |  Активных: {active}  |  Ограничено: {restricted}")
        print()
        
        choice = menu([
            ("1", "📋 Список пользователей", "Просмотр всех пользователей"),
            ("2", "👤 Добавить пользователя", "Создать нового пользователя"),
            ("3", "🔧  Управление пользователем", "Конфиги, блокировка, удаление"),
            ("4", "🔗 Сервер подписок", "Управление фоновым сервисом подписок"),
            ("0", "↩ Назад", ""),
        ], "ПОЛЬЗОВАТЕЛИ")
        
        if choice == "1":
            _show_users(state)
        elif choice == "2":
            _add_user(state, app)
        elif choice == "3":
            user = _select_user(state)
            if user:
                _user_detail_menu(state, user, app)
        elif choice == "4":
            menu_subscription_server(state)
        elif choice == "0":
            return


def _user_detail_menu(state: AppState, user: User, app: ApplicationService | None = None):
    app = _application(app)
    """Детальное меню пользователя с конфигами и управлением."""
    while True:
        clear()
        update_user_traffic(state)
        
        # Панель информации о пользователе
        available, access_reason = get_user_access_status(user)
        status_icon = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        lim_str = f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "∞"
        ttl_str = user.expiry_date[:10] if user.expiry_date else "∞"
        lines = [
            kv("Статус:", f"{status_icon} {access_reason}"),
            kv("Трафик:", f"{_bytes_auto(user.traffic_used_bytes)} / {lim_str}"),
            kv("Действует до:", ttl_str),
            kv("Создан:", user.created_at[:10] if user.created_at else "—"),
        ]
        
        panel(f"Пользователь: {user.email}", lines)
        print()
        
        # Показать доступные протоколы
        from hydra.plugins import registry
        enabled_transports = [
            p for p in registry.enabled(state, PluginCategory.TRANSPORT)
            if p.meta.name != "wdtt"
        ]
        if enabled_transports:
            proto_names = ", ".join(p.meta.name for p in enabled_transports)
            info(f"Включённые протоколы: {proto_names}")
        else:
            warn("Нет включённых транспортных протоколов")
        print()
        
        block_label = "Разблокировать" if user.blocked else "Заблокировать"
        
        choice = menu([
            ("1", "🔗 Ссылки подписки", "Автоопределение клиента и специальные форматы"),
            ("2", "📄 Ручные конфиги", "Ссылки и конфиги отдельных протоколов"),
            ("3", f"🔒🔓 {block_label}", "Переключить статус блокировки"),
            ("4", "📝 Изменить лимит трафика", "Задать квоту трафика в GiB"),
            ("5", "⏳ Изменить срок действия", "Задать дату окончания подписки"),
            ("6", "❌ Удалить", "Удалить пользователя"),
            ("0", "↩ Назад", ""),
        ], f"ПОЛЬЗОВАТЕЛЬ {user.email}")
        
        if choice == "1":
            _show_subscription_links(state, user)
        elif choice == "2":
            _user_configs(state, user)
        elif choice == "3":
            _toggle_block(state, user, app)
        elif choice == "4":
            new_lim = prompt("Введите лимит трафика в GiB (0 или пусто для безлимита)", default=str(user.traffic_limit_gb or ""))
            try:
                val = float(new_lim) if new_lim.strip() else 0.0
                if not math.isfinite(val) or val < 0:
                    raise ValueError
                user.traffic_limit_gb = val
                save_state(state)
                success(f"Лимит трафика: {f'{val:g} GiB' if val else 'без ограничений'}")
                _reconcile_user_access(state, user, app)
                prompt("Нажмите Enter")
            except ValueError:
                error("Лимит должен быть неотрицательным конечным числом.")
                prompt("Нажмите Enter")
        elif choice == "5":
            curr_ttl = user.expiry_date[:10] if user.expiry_date else ""
            new_exp = prompt("Введите срок действия подписки (ГГГГ-ММ-ДД, или пусто для безлимита)", default=curr_ttl)
            if not new_exp.strip():
                user.expiry_date = ""
                save_state(state)
                success(f"Подписка для {user.email} сделана бессрочной")
            else:
                try:
                    datetime.strptime(new_exp.strip(), "%Y-%m-%d")
                    user.expiry_date = f"{new_exp.strip()}T23:59:59Z"
                    save_state(state)
                    success(f"Срок действия подписки для {user.email} установлен до {new_exp.strip()}")
                except ValueError:
                    error("Неверный формат даты! Используйте ГГГГ-ММ-ДД.")
                    prompt("Нажмите Enter")
                    continue
            _reconcile_user_access(state, user, app)
            prompt("Нажмите Enter")
        elif choice == "6":
            if confirm(f"Удалить {user.email}?", default=False):
                app.remove_user(state, user.email)
                success(f"Пользователь {user.email} удалён")
                prompt("Нажмите Enter")
                return
        elif choice == "0":
            return


def _reconcile_user_access(state: AppState, user: User, app: ApplicationService | None = None) -> None:
    app = _application(app)
    """Немедленно применяет новые TTL/квоту к серверным конфигурациям."""
    entitled, reason = get_user_entitlement_status(user)
    if not entitled and not user.blocked:
        app.block_user(state, user.email)
        warn(f"Доступ отключён: {reason}.")
    elif entitled and user.blocked:
        if confirm("Ограничения больше не превышены. Разблокировать пользователя?", default=True):
            app.unblock_user(state, user.email)
            success("Пользователь разблокирован")


def install_sub_systemd_service(state: AppState) -> bool:
    """Генерирует и записывает systemd-юнит для сервера подписок."""
    install_dir = "/opt/hydra"
    for candidate in ("/opt/hydra", "/opt/HYDRA-ULTIMATE", "/root/HYDRA-ULTIMATE"):
        if Path(candidate).exists():
            install_dir = candidate
            break
            
    host = "127.0.0.1" if getattr(state.network, "sub_domain", "") else "0.0.0.0"
    content = f"""[Unit]
Description=HYDRA Subscription Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
Environment=PYTHONPATH={install_dir}
ExecStart=/usr/bin/python3 -m hydra.services.subscriptions.generator --host {host} --port 9443
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    return install_service("hydra-sub", content)


def _obtain_cert_for_sub(state: AppState) -> bool:
    sub_domain = getattr(state.network, "sub_domain", "")
    if not sub_domain:
        error("Сначала настройте домен подписок.")
        return False

    # Проверяем, есть ли уже валидный сертификат
    from pathlib import Path
    cert_path = Path(f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem")
    key_path = Path(f"/etc/letsencrypt/live/{sub_domain}/privkey.pem")
    if cert_path.exists() and key_path.exists():
        try:
            r = HOST.run(
                ["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(cert_path)],
                capture_output=True
            )
            if r.returncode == 0:
                success(f"Сертификат для {sub_domain} уже существует и действителен.")
                return True
        except Exception:
            pass
        
    info(f"Получение SSL-сертификата для {sub_domain} через certbot...")
    import shutil
    if not shutil.which("certbot"):
        info("Установка certbot...")
        HOST.run(["apt-get", "update"], capture_output=True)
        HOST.run(["apt-get", "install", "-y", "certbot"], capture_output=True)
        
    services_to_stop = ["haproxy", "caddy-naive", "nginx", "apache2"]
    was_running = []
    for s in services_to_stop:
        r = HOST.run(["systemctl", "is-active", s], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            info(f"Временно останавливаем {s} для освобождения порта 80...")
            HOST.run(["systemctl", "stop", s])
            was_running.append(s)
        
    HOST.run(["ufw", "allow", "80/tcp"], capture_output=True)
    
    r = HOST.run([
        "certbot", "certonly", "--standalone",
        "-d", sub_domain,
        "--non-interactive", "--agree-tos",
        "--register-unsafely-without-email",
        "--keep-until-expiring",
    ], capture_output=True, text=True)
    
    for s in reversed(was_running):
        info(f"Запускаем {s} обратно...")
        HOST.run(["systemctl", "start", s])
        
    if r.returncode == 0:
        success("Сертификат успешно получен!")
        return True
    else:
        error("Ошибка работы certbot!")
        if r.stderr or r.stdout:
            print(f"Вывод: {r.stderr or r.stdout}")
        return False


def menu_subscription_server(state: AppState):
    """Управление сервером подписок."""
    from hydra.core.systemd import is_active as is_svc_active, start, stop, restart
    from hydra.services.subscriptions.generator import find_any_cert
    
    while True:
        clear()
        title("Сервер подписок")
        
        active = is_svc_active("hydra-sub")
        status_str = f"{GREEN}🟢 АКТИВЕН{NC}" if active else f"{RED}🔴 НЕ АКТИВЕН{NC}"
        
        cert_file, key_file = find_any_cert(state)
        cert_status = f"{GREEN}Установлен ({cert_file}){NC}" if cert_file else f"{RED}Отсутствует (Необходим для HTTPS!){NC}"
        
        sub_domain = getattr(state.network, "sub_domain", "")
        domain_status = f"{CYAN}{sub_domain}{NC}" if sub_domain else f"{YELLOW}[НЕ НАСТРОЕН] (Используется IP){NC}"
        
        from hydra.utils.net import public_ip
        host = sub_domain or state.network.domain or state.network.server_ip or public_ip()
        base_url = f"https://{host}"
        if not sub_domain:
            base_url += ":9443"
        base_url += "/sub/<UUID>"
        
        lines = [
            kv("Статус службы:", status_str),
            kv("Домен подписок:", domain_status),
            kv("SSL-сертификат:", cert_status),
            kv("Базовый URL:", f"{CYAN}{base_url}{NC}"),
        ]
        panel("СОСТОЯНИЕ СЕРВЕРА", lines)
        print()
        
        opts = [
            ("1", "▶️  Запустить / Включить автозапуск", "Запустить службу hydra-sub"),
            ("2", "⏹️  Остановить / Отключить автозапуск", "Остановить службу hydra-sub"),
            ("3", "🔄 Перезапустить", "Перезапустить службу hydra-sub"),
            ("4", "🌐 Настроить домен подписок", ""),
        ]
        
        if sub_domain and not cert_file:
            opts.append(("5", "🔑 Получить SSL-сертификат через Certbot", "Standalone HTTP challenge"))
            
        opts.append(("0", "↩ Назад", ""))
        
        choice = menu(opts, "СЕРВЕР ПОДПИСОК")
        
        if choice == "0":
            return
        elif choice == "1":
            if not cert_file:
                error("Нельзя запустить сервер подписок без SSL-сертификата!")
                prompt("Нажмите Enter")
                continue
                
            install_sub_systemd_service(state)
            if start("hydra-sub"):
                success("Служба hydra-sub успешно запущена")
            else:
                error("Не удалось запустить службу. Проверьте systemctl status hydra-sub")
            prompt("Нажмите Enter")
            
        elif choice == "2":
            if stop("hydra-sub"):
                HOST.run(["systemctl", "disable", "hydra-sub"], capture_output=True)
                success("Служба hydra-sub остановлена и отключена из автозапуска")
            else:
                error("Не удалось остановить службу")
            prompt("Нажмите Enter")
            
        elif choice == "3":
            if not cert_file:
                error("Нельзя перезапустить сервер подписок без SSL-сертификата!")
                prompt("Нажмите Enter")
                continue
            if restart("hydra-sub"):
                success("Служба hydra-sub успешно перезапущена")
            else:
                error("Не удалось перезапустить службу")
            prompt("Нажмите Enter")
            
        elif choice == "4":
            new_domain = prompt("Введите выделенный домен подписок (например, sub.example.com)", default=sub_domain)
            state.network.sub_domain = new_domain.strip()
            save_state(state)
            
            from hydra.core import sni_router
            sni_router.rebuild(state)
            
            success(f"Домен подписок обновлён: {new_domain}")
            install_sub_systemd_service(state)
            prompt("Нажмите Enter")
            
        elif choice == "5" and sub_domain and not cert_file:
            if _obtain_cert_for_sub(state):
                from hydra.core import sni_router
                sni_router.rebuild(state)
                restart("hydra-sub")
            prompt("Нажмите Enter")


def _show_subscription_links(state: AppState, user: User) -> None:
    """Показывает каноническую подписку отдельно от ручных конфигов."""
    clear()
    title(f"Подписка: {user.email}")
    urls = get_subscription_urls(user, state)
    available, reason = get_user_access_status(user)
    panel("ДОСТУП", [
        kv("Статус:", f"{GREEN if available else RED}{reason}{NC}"),
        kv("Обновление:", "каждые 6 часов"),
    ])
    print()
    print(f"  {BOLD}Основная ссылка (рекомендуется){NC}")
    print(f"  {DIM}NekoBox и Throne определяются автоматически по приложению.{NC}")
    print(f"  {CYAN}{urls['auto']}{NC}\n")
    print(f"  {BOLD}Ручной выбор формата{NC}")
    print(f"  NekoBox:       {CYAN}{urls['nekobox']}{NC}")
    print(f"  Throne:        {CYAN}{urls['throne']}{NC}")
    print(f"  Sing-Box JSON: {CYAN}{urls['singbox']}{NC}")
    print(f"\n  {DIM}Ссылка содержит секретный токен — передавайте её только владельцу.{NC}")
    prompt("Нажмите Enter")


def _user_configs(state: AppState, user: User):
    """Показывает конфиги и ссылки для всех протоколов."""
    clear()
    title(f"Конфигурации для пользователя: {user.email}")
    
    # Проверка наличия qrcode
    try:
        import qrcode
    except ImportError:
        warn("Библиотека qrcode не установлена, QR-коды не будут отображаться.")
        info("Установите её командой: pip3 install qrcode")
        print()

    from hydra.plugins import registry
    enabled_transports = [
        p for p in registry.enabled(state, PluginCategory.TRANSPORT)
        if p.meta.name != "wdtt"
    ]
    
    if not enabled_transports:
        warn("Нет включённых транспортных протоколов")
        prompt("Нажмите Enter")
        return
    
    for p in enabled_transports:
        # Ссылки
        links = []
        try:
            if hasattr(p, "client_links"):
                links = p.client_links(user, state)
            else:
                l = p.client_link(user, state)
                if l:
                    links = [l]
        except Exception:
            pass
            
        # Конфиг
        try:
            if p.meta.name == "telemt":
                from hydra.plugins.telemt.plugin import TelemtPlugin
                from hydra.plugins.telemt.telemt_ios_fix import status as ios_status
                from hydra.utils.net import public_ip
                
                ps = state.protocols.setdefault("telemt", state.protocols.get("telemt") or PluginState())
                cfg = ps.config or {}
                port = cfg.get("port", 8443)
                domain = cfg.get("tls_domain")
                if domain is None:
                    domain = state.network.domain
                
                secret = TelemtPlugin._derive_secret(user.uuid)
                server_ip = state.network.server_ip or public_ip()
                tls_secret = TelemtPlugin._make_tls_secret(secret, domain) if domain else secret
                
                box_lines = []
                box_lines.append(f"{YELLOW}{BOLD}Основная ссылка (ПК/Android):{NC}")
                link_main = f"tg://proxy?server={server_ip}&port={port}&secret={tls_secret}"
                link_width = PANEL_W - 6
                for chunk in [link_main[i:i+link_width] for i in range(0, len(link_main), link_width)]:
                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                
                try:
                    ios_st = ios_status()
                    if ios_st.get("enabled"):
                        box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
                        box_lines.append(f"{YELLOW}{BOLD}Ссылка с iOS-фиксом (порт {ios_st['ext_port']}):{NC}")
                        link_ios = f"tg://proxy?server={server_ip}&port={ios_st['ext_port']}&secret={tls_secret}"
                        for chunk in [link_ios[i:i+link_width] for i in range(0, len(link_ios), link_width)]:
                            box_lines.append(f"  {CYAN}{chunk}{NC}")
                except Exception:
                    pass
                
                panel(f"🔧  {p.meta.name.upper()} CONFIG", box_lines)
                
                continue

            if p.meta.name == "amneziawg":
                ps = state.protocols.get("amneziawg")
                has_mobile = ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]
                profiles = ["desktop"]
                if has_mobile:
                    profiles.append("mobile")

                for prof in profiles:
                    link_prof = ""
                    vpn_link = ""
                    try:
                        link_prof = p.client_link(user, state, profile=prof)
                    except Exception:
                        pass
                    try:
                        vpn_link = p.amnezia_link(user, state, profile=prof)
                    except Exception:
                        pass
                    
                    try:
                        conf = p.generate_client_config(user, state, profile=prof)
                        if conf:
                            box_lines = []
                            label_ru = "ПК / Desktop" if prof == "desktop" else "Смартфон / Mobile"
                            link_width = PANEL_W - 6
                            
                            # Показываем WireGuard/AmneziaWG ссылку
                            if link_prof:
                                box_lines.append(f"{YELLOW}{BOLD}Ссылка для подключения (WireGuard / URL - {label_ru}):{NC}")
                                for chunk in [link_prof[i:i+link_width] for i in range(0, len(link_prof), link_width)]:
                                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                                box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")

                            if vpn_link and vpn_link != link_prof:
                                box_lines.append(f"{YELLOW}{BOLD}Импорт в AmneziaVPN:{NC}")
                                for chunk in [vpn_link[i:i+link_width] for i in range(0, len(vpn_link), link_width)]:
                                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                                box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")

                            
                            # Показываем конфиг
                            box_lines.append(f"{GREEN}{BOLD}Файл конфигурации (Client Config - {label_ru}):{NC}")
                            for line in conf.splitlines():
                                box_lines.append(f"  {DIM}{line.rstrip()}{NC}")
                            
                            panel(f"🔧  {p.meta.name.upper()} {prof.upper()} CONFIG", box_lines)
                            
                            # QR-код (если qrcode установлен)
                            try:
                                import qrcode
                                qr = qrcode.QRCode(border=1)
                                qr.add_data(conf)
                                print(f"\n  {BOLD}{WHITE}Отсканируйте QR-код для быстрого импорта ({label_ru}):{NC}")
                                qr.print_ascii(invert=True)
                            except Exception as e:
                                error(f"  Не удалось создать QR-код: {e}")
                    except Exception as e:
                        error(f"  Ошибка получения конфигурации {p.meta.name} ({prof}): {e}")
                continue

            conf = p.generate_client_config(user, state)
            if conf or links:
                box_lines = []
                
                # Показываем ссылку, если она есть
                if links:
                    label = "Ссылки для подключения (URL):" if len(links) > 1 else "Ссылка для подключения (URL):"
                    box_lines.append(f"{YELLOW}{BOLD}{label}{NC}")
                    # Оборачиваем ссылку по ширине коробки (PANEL_W - 6)
                    link_width = PANEL_W - 6
                    for idx, l in enumerate(links):
                        if idx > 0:
                            box_lines.append(f"  {DIM}{'┄' * (PANEL_W - 8)}{NC}")
                        for chunk in [l[i:i+link_width] for i in range(0, len(l), link_width)]:
                            box_lines.append(f"  {CYAN}{chunk}{NC}")
                    box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
                
                if conf:
                    box_lines.append(f"{GREEN}{BOLD}Файл конфигурации (Client Config):{NC}")
                    for line in conf.splitlines():
                        box_lines.append(f"  {DIM}{line.rstrip()}{NC}")
                
                panel(f"🔧  {p.meta.name.upper()} CONFIG", box_lines)
                

        except Exception as e:
            error(f"  Ошибка получения конфигурации {p.meta.name}: {e}")
            
    print()
    prompt("Нажмите Enter")


def _show_users(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    title("Список пользователей")
    print()
    update_user_traffic(state)
    print(f"  {BOLD}{'Пользователь':<30} {'Статус':<17} {'Трафик':>20} {'Действует до':>12}{NC}")
    print(f"  {DIM}{'─' * 83}{NC}")
    for u in sorted(state.users, key=lambda item: item.email.casefold()):
        available, reason = get_user_access_status(u)
        color = GREEN if available else RED
        limit = f"{u.traffic_limit_gb:g} GiB" if u.traffic_limit_gb else "∞"
        traffic = f"{_bytes_auto(u.traffic_used_bytes)} / {limit}"
        expiry = u.expiry_date[:10] if u.expiry_date else "∞"
        print(
            f"  {color}{'●'}{NC} {BOLD}{u.email:<28}{NC} "
            f"{color}{reason:<17}{NC} {traffic:>20} {expiry:>12}"
        )
    print()
    prompt("Нажмите Enter")


def _add_user(state: AppState, app: ApplicationService | None = None):
    app = _application(app)
    """Добавление нового пользователя с автогенерацией конфигов."""
    clear()
    title("Добавить пользователя")
    
    # Показать какие протоколы создадут конфиги
    from hydra.plugins import registry
    enabled_transports = [
        p for p in registry.enabled(state, PluginCategory.TRANSPORT)
        if p.meta.name != "wdtt"
    ]
    
    if enabled_transports:
        proto_names = ", ".join(p.meta.name for p in enabled_transports)
        info(f"Конфиги будут созданы для: {proto_names}")
    else:
        warn("Нет включённых протоколов — конфиги не будут созданы")
    print()
    
    email = prompt("Email пользователя").strip().lower()
    if not email:
        return
    if not re.fullmatch(r"\S+", email):
        error("Введите имя пользователя или email без пробелов.")
        prompt("Нажмите Enter")
        return
    
    # Проверка дубликата
    if any(existing.email.casefold() == email.casefold() for existing in state.users):
        error(f"Пользователь {email} уже существует")
        prompt("Нажмите Enter")
        return
    
    user = User(
        email=email,
        uuid=str(_uuid.uuid4()),
        created_at=datetime.now().isoformat(),
    )
    
    app.add_user(state, user)
    
    success(f"Пользователь {email} создан")
    if enabled_transports:
        success(f"Конфиги сгенерированы для {len(enabled_transports)} протокол(ов)")
    
    prompt("Нажмите Enter")


def _toggle_block(state: AppState, user: User, app: ApplicationService | None = None):
    app = _application(app)
    """Переключает блокировку пользователя."""
    if user.blocked:
        entitled, reason = get_user_entitlement_status(user)
        if not entitled:
            error(f"Нельзя разблокировать: {reason}. Сначала измените лимит или срок действия.")
            prompt("Нажмите Enter")
            return
        app.unblock_user(state, user.email)
        success(f"{user.email} разблокирован")
    else:
        app.block_user(state, user.email)
        success(f"{user.email} заблокирован")
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

def _unit_active(unit: str) -> bool:
    """Безопасно проверяет systemd-юнит, в том числе вне Linux."""
    try:
        result = HOST.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _is_enter_pressed() -> bool:
    import select
    import os
    if os.name == "nt":
        import msvcrt
        if msvcrt.kbhit():
            if msvcrt.getch() in (b'\r', b'\n'):
                return True
        return False
    else:
        i, o, e = select.select([sys.stdin], [], [], 0.0)
        for s in i:
            if s == sys.stdin:
                sys.stdin.readline()
                return True
        return False


def menu_monitoring(state: AppState):
    while True:
        state = load_state()
        clear()
        
        # Сбор быстрых системных метрик для панели
        load_str = "—"
        ram_str = "—"
        if os.name != "nt":
            try:
                avg1, avg5, _ = os.getloadavg()
                load_str = f"{avg1:.2f}, {avg5:.2f}"
            except Exception:
                pass
            try:
                _, _, r_pct = _read_proc_mem()
                ram_str = f"{r_pct:.0f}%"
            except Exception:
                pass
                
        transport_plugins = transports()
        enabled_names = {
            plugin.meta.name for plugin in transport_plugins
            if state.protocols.get(plugin.meta.name)
            and state.protocols[plugin.meta.name].enabled
        }
        running_count = 0
        for plugin in transport_plugins:
            if plugin.meta.name not in enabled_names:
                continue
            try:
                running_count += int(plugin.status().running)
            except Exception:
                pass
        users_count = len(state.users)
        active_users = sum(not user.blocked for user in state.users)
        sync_active = _unit_active("hydra-sync-agent.timer")
        traffic_active = _unit_active("hydra-traffic-daemon.service")
        
        lines = [
            f"  🔌 {BOLD}Протоколы:{NC} {GREEN}{running_count} работают{NC} / {len(enabled_names)} включено",
            f"  👥 {BOLD}Пользователи:{NC} {CYAN}{active_users} активны{NC} / {users_count} всего",
            f"  🖥️  {BOLD}Система:{NC} Load Avg {YELLOW}{load_str}{NC}  │  RAM {YELLOW}{ram_str}{NC}",
            f"  ⚙️  {BOLD}Фоновые службы:{NC} Sync Agent "
            f"{f'{GREEN}●{NC}' if sync_active else f'{DIM}○{NC}'}  Clash API "
            f"{f'{GREEN}●{NC}' if traffic_active else f'{DIM}○{NC}'}",
        ]
        panel("💻  Состояние системы", lines)

        choice = menu(
            [("1", "📊 Потребление трафика", "Сводная статистика по протоколам и пользователям"),
             ("2", "🔌 Подключения и активность", "Активные сессии и недавние запросы пользователей"),
             ("3", "📈 Живой монитор CPU/RAM", "Нагрузка системы, скорость сети и метрики"),
             ("4", "⚙️ Фоновые службы и логи", "Учёт трафика, синхронизация и системные журналы"),
             ("0", "↩ Назад", "")],
            "МОНИТОРИНГ",
        )
        if choice == "0":
            return
        elif choice == "1":
            _show_traffic_combined(state)
        elif choice == "2":
            _show_connections(state)
        elif choice == "3":
            _show_realtime_sys_monitor()
        elif choice == "4":
            _menu_service_settings(state)


def _menu_service_settings(state: AppState):
    while True:
        state = load_state()
        clear()
        sync_active = _unit_active("hydra-sync-agent.timer")
        clash_enabled = bool(getattr(state.network, "clash_api_enabled", False))
        traffic_active = _unit_active("hydra-traffic-daemon.service")
        panel("Фоновые службы", [
            kv("Sync Agent:", f"{GREEN}активно 🟢{NC}" if sync_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Clash API:", (
                f"{GREEN}активно 🟢{NC}" if clash_enabled and traffic_active
                else f"{YELLOW}ошибка службы 🟡{NC}" if clash_enabled
                else f"{DIM}неактивно ⚪{NC}"
            )),
        ])
        choice = menu([
            ("1", "📋 Просмотр системных логов", "Sing-Box, Sync-Agent, Fail2ban и др."),
            ("2", "🔄 Sync Agent", "Проверка лимитов, сроков действия и обновление WARP-списков"),
            ("3", "📊 Clash API", "Локальный API Sing-Box и демон статистики трафика"),
            ("0", "↩ Назад", "")
        ], "СЕРВИСНЫЕ НАСТРОЙКИ")
        
        if choice == "0":
            break
        elif choice == "1":
            _menu_logs(state)
        elif choice == "2":
            _menu_sync_agent(state)
        elif choice == "3":
            _menu_clash_api(state)


def _show_traffic_combined(state: AppState):
    sort_by = "traffic"
    show_zero_users = True

    def share_bar(value: int, total: int, width: int = 11) -> str:
        ratio = min(1.0, value / total) if total > 0 else 0.0
        filled = int(round(ratio * width))
        return (
            f"{CYAN}{'█' * filled}{DIM}{'░' * (width - filled)}{NC} "
            f"{ratio * 100:5.1f}%"
        )

    while True:
        clear()
        title("📊 Потребление трафика")
        print()
        
        # Refresh from the latest on-disk state. This avoids overwriting daemon
        # increments with the stale object that opened the main menu.
        state = refresh_traffic_state()
        by_protocol = protocol_totals(state)
        enabled_names = {
            plugin.meta.name for plugin in enabled(state, PluginCategory.TRANSPORT)
        }
        labels = {
            "amneziawg": "AmneziaWG", "naive": "NaiveProxy",
            "anytls": "AnyTLS", "mieru": "Mieru",
            "trusttunnel": "TrustTunnel", "shadowtls": "ShadowTLS",
            "hysteria2": "Hysteria2", "snell": "Snell",
            "telemt": "Telemt", "wdtt": "qWDTT",
        }
        order = [
            "amneziawg", "naive", "anytls", "mieru", "trusttunnel",
            "shadowtls", "hysteria2", "snell", "telemt", "wdtt",
        ]
        names = [name for name in order if name in enabled_names or by_protocol.get(name, 0)]
        names.extend(sorted(set(by_protocol) - set(names)))

        aggregate_totals = {
            name: int(stats.get("traffic_used_bytes", 0))
            for name, stats in state.install.get("protocol_traffic_totals", {}).items()
            if isinstance(stats, dict)
        }
        user_total = sum(max(0, int(user.traffic_used_bytes)) for user in state.users)
        attributed_user_total = sum(
            max(0, int(stats.get("traffic_used_bytes", 0)))
            for user in state.users
            for stats in user.credentials.values()
            if isinstance(stats, dict)
        )
        legacy_unattributed = max(0, user_total - attributed_user_total)
        protocol_total = sum(by_protocol.values())
        total_traffic = protocol_total + legacy_unattributed
        active_users = sum(not user.blocked for user in state.users)
        limited_users = sum(user.traffic_limit_gb > 0 for user in state.users)

        panel("📊 Сводка трафика", [
            kv("Всего учтено:", f"{BOLD}{CYAN}{_bytes_auto(total_traffic)}{NC}"),
            kv("Пользователи:", f"{active_users} активны / {len(state.users)} всего"),
            kv("С лимитом:", str(limited_users)),
        ])

        print()
        print(f"  {BOLD}По протоколам{NC}")
        print(f"  {BOLD}{'Протокол':<15} {'Трафик':>12}  {'Доля':<18} {'Учёт':<13} {'Статус':<8}{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        for name in names:
            status = f"{GREEN}включён{NC}" if name in enabled_names else f"{DIM}история{NC}"
            accounting_text = "общий" if name in aggregate_totals else "по пользов."
            accounting_color = YELLOW if name in aggregate_totals else DIM
            accounting = f"{accounting_color}{accounting_text:<13}{NC}"
            value = by_protocol.get(name, 0)
            print(
                f"  {labels.get(name, name):<15} {GREEN}{_bytes_auto(value):>12}{NC}  "
                f"{share_bar(value, total_traffic):<18} {accounting} {status}"
            )
        if legacy_unattributed:
            print(
                f"  {'Старая статист.':<15} {YELLOW}{_bytes_auto(legacy_unattributed):>12}{NC}  "
                f"{share_bar(legacy_unattributed, total_traffic):<18} {DIM}без разбивки{NC}"
            )
        print()
        
        print(f"  {BOLD}По пользователям{NC}")
        users_sorted = list(state.users)
        if not show_zero_users:
            users_sorted = [user for user in users_sorted if user.traffic_used_bytes > 0]
        if sort_by == "traffic":
            users_sorted.sort(key=lambda u: u.traffic_used_bytes, reverse=True)
        elif sort_by == "name":
            users_sorted.sort(key=lambda u: u.email.lower())
        elif sort_by == "limit":
            users_sorted.sort(key=lambda u: u.traffic_limit_gb, reverse=True)
        elif sort_by == "expiry":
            def get_expiry(u):
                if not u.expiry_date:
                    return "9999-12-31"
                return u.expiry_date
            users_sorted.sort(key=get_expiry)

        print(f"  {BOLD}{'#':<3} {'Пользователь':<20} {'Трафик':>12} {'Лимит':>10} {'Исп.':>7} {'Статус':<9} {'Срок':<10}{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        for i, u in enumerate(users_sorted, 1):
            used = u.traffic_used_bytes
            status_text = "блок" if u.blocked else "активен"
            status_color = RED if u.blocked else GREEN
            status_str = f"{status_color}{status_text:<9}{NC}"
            
            expiry_str = "бессрочно"
            if u.expiry_date:
                try:
                    expiry = datetime.fromisoformat(u.expiry_date)
                    now = datetime.now(expiry.tzinfo)
                    delta = expiry - now
                    if delta.days < 0:
                        expiry_str = f"{RED}истёк{NC}"
                    else:
                        expiry_str = f"{delta.days}дн"
                except Exception:
                    expiry_str = u.expiry_date[:10]

            limit_bytes = int(u.traffic_limit_gb * 1073741824)
            lim_str = f"{u.traffic_limit_gb:.1f} GiB" if limit_bytes else "∞"
            usage_str = f"{min(999, used / limit_bytes * 100):.0f}%" if limit_bytes else "—"
            email = u.email if len(u.email) <= 20 else u.email[:17] + "..."
            print(
                f"  {i:<3d} {BOLD}{email:<20}{NC} {_bytes_auto(used):>12} "
                f"{lim_str:>10} {usage_str:>7} {status_str} {expiry_str:<10}"
            )

        if not users_sorted:
            print(f"  {DIM}Нет пользователей с ненулевым трафиком.{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        shown = len(users_sorted)
        print(f"  {DIM}Показано: {shown}/{len(state.users)}{NC}")
        print()

        sort_labels = {
            "traffic": "по трафику", "name": "по имени",
            "limit": "по лимиту", "expiry": "по сроку",
        }
        choice = menu([
            ("1", f"{'✓ ' if sort_by == 'traffic' else ''}Сортировать по трафику", ""),
            ("2", f"{'✓ ' if sort_by == 'name' else ''}Сортировать по имени", ""),
            ("3", f"{'✓ ' if sort_by == 'limit' else ''}Сортировать по лимиту", ""),
            ("4", f"{'✓ ' if sort_by == 'expiry' else ''}Сортировать по сроку", ""),
            ("Z", "Показать всех пользователей" if not show_zero_users else "Скрыть пользователей без трафика", ""),
            ("D", "🔍 Статистика пользователя", ""),
            ("0", "↩ Назад", "")
        ], f"УПРАВЛЕНИЕ · {sort_labels[sort_by].upper()}")
        
        if choice == "0":
            break
        elif choice == "1":
            sort_by = "traffic"
        elif choice == "2":
            sort_by = "name"
        elif choice == "3":
            sort_by = "limit"
        elif choice == "4":
            sort_by = "expiry"
        elif choice.upper() == "Z":
            show_zero_users = not show_zero_users
        elif choice.upper() == "D":
            u = _select_user(state, "Выберите пользователя для просмотра деталей")
            if u:
                _show_user_detail(state, u)


def _show_connections(state: AppState):
    import time
    from hydra.plugins.registry import enabled
    from hydra.plugins.base import PluginCategory
    
    while True:
        clear()
        title("🔌 Подключения и активность")
        print()
        
        state = load_state()
        all_clients = []
        from hydra.services.active_connections import tracked_active_connections
        all_clients.extend(tracked_active_connections(state))
        for p in enabled(state, PluginCategory.TRANSPORT):
            # These are represented by the attributed Clash API snapshot. ss
            # sees only internal proxy legs and cannot identify their users.
            if p.meta.name == "naive":
                recent = getattr(p, "recent_connections", None)
                if recent:
                    try:
                        for client in recent(state):
                            row = dict(client)
                            row["plugin"] = "naive"
                            all_clients.append(row)
                    except Exception:
                        pass
                continue
            if p.meta.name in {
                "anytls", "mieru", "trusttunnel", "shadowtls", "hysteria2", "snell",
            }:
                continue
            try:
                try:
                    clients = p.connected_clients(state)
                except TypeError:
                    clients = p.connected_clients()
                    
                for c in clients:
                    row = dict(c)
                    row["plugin"] = p.meta.name
                    all_clients.append(row)
            except Exception:
                pass
        all_clients.sort(key=lambda item: (
            str(item.get("plugin", "")), str(item.get("email", "")).lower(),
        ))
                
        if not all_clients:
            print(f"  {YELLOW}Нет активных подключений в данный момент.{NC}")
            print()
        else:
            print(f"  {BOLD}{'Протокол':<12} {'Пользователь':<30} {'Rx / Tx':<20} {'Активность':<15}{NC}")
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
            for c in all_clients:
                plugin_name = c.get("plugin", "unknown")
                email = c.get("email", "?")
                profiles = c.get("profiles", [])
                if profiles:
                    email = f"{email} [{'/'.join(profiles)}]"
                elif c.get("connections", 0) > 1:
                    email = f"{email} ({c['connections']} сесс.)"
                rx = c.get("rx", 0)
                tx = c.get("tx", 0)
                online = c.get("online", True)
                
                activity = "—"
                handshake = c.get("last_handshake", 0)
                if handshake > 0:
                    elapsed = int(time.time()) - handshake
                    if elapsed < 0:
                        activity = "сейчас"
                    elif elapsed < 60:
                        activity = f"{elapsed} сек"
                    elif elapsed < 3600:
                        activity = f"{elapsed // 60} мин"
                    else:
                        activity = f"{elapsed // 3600} ч"
                elif online:
                    activity = "активен"
                    
                recent = c.get("activity_kind") == "recent"
                status_ico = f"{GREEN}●{NC}" if online else (f"{YELLOW}◐{NC}" if recent else f"{DIM}●{NC}")
                traffic_str = f"{_bytes_auto(rx)} / {_bytes_auto(tx)}" if (rx or tx) else "—"
                
                email_disp = email
                if len(email_disp) > 30:
                    email_disp = email_disp[:27] + "..."
                    
                print(f"  {plugin_name:<12} {status_ico} {BOLD}{email_disp:<28}{NC} {traffic_str:<20} {activity:<15}")
            print()
            print(f"  {DIM}● Активно ◐ Активно (5 мин){NC}")

        from hydra.services.active_connections import traffic_daemon_fresh
        if not state.network.clash_api_enabled:
            print(f"  {YELLOW}AnyTLS/Mieru/TrustTunnel/ShadowTLS не показаны: Clash API и демон статистики выключены.{NC}")
        elif not traffic_daemon_fresh(state):
            print(f"  {YELLOW}Данные Clash API устарели: проверьте службу hydra-traffic-daemon.{NC}")
            
        choice = menu([
            ("R", "🔄 Обновить список", ""),
            ("0", "↩ Назад", "")
        ], "ПОДКЛЮЧЕНИЯ И АКТИВНОСТЬ")
        
        if choice == "0":
            break


def _show_status():
    clear()
    title("🚦 Статус протоколов")
    print()
    
    st = status_all()
    
    print(f"  {BOLD}{'Протокол':<15} {'Порт':<7} {'Состояние':<12} {'Автозапуск':<12}{NC}")
    print(f"  {DIM}{'─' * 55}{NC}")
    
    for name, s in st.items():
        ico = f"{GREEN}запущен{NC}" if s["running"] else (f"{YELLOW}остановлен{NC}" if s["installed"] else f"{DIM}не уст.{NC}")
        port_str = str(s['port']) if s['port'] else "—"
        autostart_str = "вкл" if s.get("enabled", False) else "выкл"
        
        print(f"  {name:<15} {port_str:<7} {ico:<12} {autostart_str:<12}")
        
    print()
    prompt("Нажмите Enter для возврата")


def _read_proc_cpu() -> tuple[float, float]:
    return system_monitor.read_proc_cpu()


def _read_proc_mem() -> tuple[int, int, float]:
    return system_monitor.read_proc_mem()


def _read_proc_net() -> tuple[int, int]:
    return system_monitor.read_proc_net()


def _show_realtime_sys_monitor():
    system_monitor.show_realtime(
        enter_pressed=_is_enter_pressed,
        bytes_auto=_bytes_auto,
        read_cpu=_read_proc_cpu,
        read_mem=_read_proc_mem,
        read_net=_read_proc_net,
    )


def _menu_logs(state: AppState):
    lines_count = 30
    while True:
        try:
            from hydra.services.traffic_daemon import maintain_traffic_log
            maintain_traffic_log()
        except Exception:
            pass
        clear()
        title("📋 Просмотр системных логов")
        print()
        
        # Каждый пункт явно указывает реальный источник. Большинство сервисов
        # пишут stdout/stderr в journald, а не в выдуманный log-файл.
        log_options = [
            ("1", "📋 Sing-Box", "journal", "sing-box"),
            ("2", "🔄 Sync Agent", "file", "/var/log/hydra/sync-agent.log"),
            ("3", "📊 Clash API", "file", "/var/log/hydra/traffic-daemon.log"),
            ("4", "🔗 qWDTT", "journal", "wdtt"),
            ("5", "🌐 Caddy L4", "journal", "caddy-l4"),
            ("6", "📨 Telemt", "journal", "telemt"),
            ("7", "🔐 DNSCrypt", "journal", "dnscrypt-proxy"),
            ("8", "🔒 Fail2ban", "journal", "fail2ban"),
            ("9", "🌐 Naive access", "file", "/var/log/caddy-naive/access.log"),
            ("A", "🍯 Honeypot events", "file", "/var/log/hydra-honeypot.log"),
            ("B", "📦 Сервер подписок", "journal", "hydra-sub"),
            ("C", "🤖 Telegram Admin Bot", "journal", "hydra-tg-admin"),
            ("D", "🤖 Telegram Client Bot", "journal", "hydra-tg-bot"),
            ("E", "🛠 HYDRA install", "file", "/var/log/hydra/install.log"),
        ]
            
        print(f"  {BOLD}Текущий лимит строк для просмотра:{NC} {GREEN}{lines_count}{NC}\n")
        
        opts = []
        for key, name, source_type, source in log_options:
            source_label = source if source_type == "file" else f"journalctl -u {source}"
            opts.append((key, name, f"{source_label} · {_log_source_status(source_type, source)}"))
            
        opts += [
            ("-", "", ""),
            ("L", f"📝 Изменить лимит строк ({lines_count})", ""),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(opts, "ВЫБОР ЛОГ-ФАЙЛА")
        if choice == "0":
            break
        elif choice.upper() == "L":
            try:
                new_limit = int(prompt("Введите количество строк", str(lines_count)))
                if new_limit > 0:
                    lines_count = new_limit
            except ValueError:
                warn("Введите корректное число.")
                prompt("Нажмите Enter")
        else:
            selected_source = None
            selected_type = ""
            selected_title = ""
            for key, name, source_type, source in log_options:
                if choice == key:
                    selected_source = source
                    selected_type = source_type
                    selected_title = name
                    break
                    
            if selected_source:
                _show_log_source(selected_title, selected_type, selected_source, lines_count)


def _unit_known(unit: str) -> bool:
    return log_viewer.unit_known(unit)


def _log_source_status(source_type: str, source: str) -> str:
    if source_type != "file" and not _unit_active(source) and not _unit_known(source):
        return "не установлено"
    return log_viewer.source_status(
        source_type, source, unit_active=_unit_active, bytes_auto=_bytes_auto,
    )


def _read_log_source(source_type: str, source: str, num_lines: int) -> tuple[list[str], str]:
    return log_viewer.read_source(source_type, source, num_lines)


def _show_log_source(title_text: str, source_type: str, source: str, num_lines: int):
    log_viewer.show_source(
        title_text, source_type, source, num_lines,
        enter_pressed=_is_enter_pressed,
    )


def _show_log_file(title_text: str, path_str: str, num_lines: int):
    """Обратная совместимость для внутренних меню с файловыми логами."""
    log_viewer.show_file(
        title_text, path_str, num_lines,
        enter_pressed=_is_enter_pressed,
    )


def _watch_log_file(title_text: str, path_str: str):
    log_viewer.watch_file(title_text, path_str, _is_enter_pressed)


def _watch_journal(title_text: str, unit: str):
    log_viewer.watch_journal(title_text, unit, _is_enter_pressed)


def _sync_agent_log_snapshot(
    log_path: Path,
    now_timestamp: float | None = None,
) -> tuple[str, str, bool]:
    return log_viewer.sync_snapshot(log_path, now_timestamp)


def _menu_sync_agent(state: AppState):
    while True:
        state = load_state()
        clear()
        
        timer_active = _unit_active("hydra-sync-agent.timer")
            
        log_path = Path("/var/log/hydra/sync-agent.log")
        last_log_line, log_freshness, log_stale = _sync_agent_log_snapshot(log_path)
        freshness_color = RED if timer_active and log_stale else DIM
                
        lines = [
            kv("Таймер (5 мин):", f"{GREEN}активен 🟢{NC}" if timer_active else f"{RED}отключен 🔴{NC}"),
            kv("Лог-файл:", f"{_bytes_auto(log_path.stat().st_size) if log_path.exists() else 'не создан'}"),
            kv("Последняя запись:", f"{DIM}{last_log_line}{NC}"),
            kv("Актуальность:", f"{freshness_color}{log_freshness}{NC}"),
        ]
        panel("Управление Sync Agent", lines)
        
        warp_auto = state.install.get("sync_warp_enabled", True)
        limits_auto = state.install.get("sync_limits_enabled", True)
        updates_auto = state.install.get("sync_updates_enabled", True)

        toggle_label = "⏹ Отключить Sync Agent" if timer_active else "▶ Включить Sync Agent"
        toggle_desc = "Остановить периодическую синхронизацию" if timer_active else "Проверять лимиты и сроки каждые 5 минут"
        
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("2", "⚡ Запустить сейчас", "Однократно проверить лимиты, сроки, WARP и обновление Sing-Box"),
            ("3", "📋 Показать лог", "Последние 30 строк sync-agent.log"),
            ("-", "", ""),
            ("4", f"🔄 Автообновление списков WARP: {GREEN}[ВКЛ]{NC}" if warp_auto else f"🔄 Автообновление списков WARP: {RED}[ВЫКЛ]{NC}",
             "Раз в 24 часа скачивать свежие правила WARP"),
            ("5", f"👥 Автопроверка лимитов: {GREEN}[ВКЛ]{NC}" if limits_auto else f"👥 Автопроверка лимитов: {RED}[ВЫКЛ]{NC}",
             "Блокировать пользователей при превышении трафика/TTL"),
            ("6", f"🆙 Автопроверка обновлений ядра: {GREEN}[ВКЛ]{NC}" if updates_auto else f"🆙 Автопроверка обновлений ядра: {RED}[ВЫКЛ]{NC}",
             "Раз в 24 часа проверять наличие обновлений Sing-Box"),
            ("0", "↩ Назад", "")
        ], "SYNC AGENT")
        
        if choice == "0":
            break
        elif choice == "1":
            if timer_active:
                info("Отключение Sync Agent...")
                if remove_unit("hydra-sync-agent"):
                    success("Sync Agent отключён")
                else:
                    error("Не удалось отключить Sync Agent")
            else:
                project_root = Path(__file__).resolve().parent.parent.parent
                ok = install_timer("hydra-sync-agent",
                    f"""[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
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
                if ok:
                    success("Sync Agent включён (каждые 5 минут)")
                else:
                    error("Не удалось включить Sync Agent")
            prompt("Нажмите Enter")
        elif choice == "2":
            info("Запуск ручной синхронизации...")
            try:
                from hydra.services.sync_agent import run_sync
                ok, message = run_sync(
                    force_update_check=True,
                    force_all_checks=True,
                )
                if ok:
                    success("Синхронизация успешно выполнена")
                else:
                    warn(f"Синхронизация завершена с ошибками: {message}")
            except Exception as e:
                error(f"Ошибка при синхронизации: {e}")
            prompt("Нажмите Enter")
        elif choice == "3":
            _show_log_file("Sync Agent", str(log_path), 30)
        elif choice == "4":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_warp_enabled", not warp_auto)
            )
        elif choice == "5":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_limits_enabled", not limits_auto)
            )
        elif choice == "6":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_updates_enabled", not updates_auto)
            )


def _menu_clash_api(state: AppState):
    while True:
        state = load_state()
        clear()
        
        enabled_status = getattr(state.network, "clash_api_enabled", False)
        daemon_active = _unit_active("hydra-traffic-daemon.service")
            
        lines = [
            kv("Clash API:", f"{GREEN}активно 🟢{NC}" if enabled_status and daemon_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Демон статистики:", f"{GREEN}активно 🟢{NC}" if daemon_active else f"{DIM}неактивно ⚪{NC}"),
        ]
        panel("Clash API", lines)
        
        toggle_label = "⏹ Отключить Clash API" if enabled_status else "▶ Включить Clash API"
        toggle_desc = "Отключить Clash API и демон статистики" if enabled_status else "Включить локальный Clash API и демон статистики"
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("0", "↩ Назад", "")
        ], "CLASH API")
        
        if choice == "0":
            break
        elif choice == "1":
            desired = not enabled_status
            state, _ = update_state(lambda latest: setattr(latest.network, "clash_api_enabled", desired))
            info("Пересборка конфигурации Sing-Box...")
            from hydra.core.orchestrator import apply_config
            if apply_config(state):
                success("Clash API включён" if desired else "Clash API отключён")
            else:
                state, _ = update_state(
                    lambda latest: setattr(latest.network, "clash_api_enabled", enabled_status)
                )
                apply_config(state)
                error(_apply_error_text("Не удалось применить настройку; прежнее состояние восстановлено"))
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  6. Безопасность — полноценное меню
# ═════════════════════════════════════════════════════════════════════════════

def menu_security(state: AppState):
    from hydra.plugins.registry import get as get_plugin
    while True:
        clear()
        st = status_all()

        security_p_lines = []
        p_f2b = get_plugin("fail2ban")
        p_hp = get_plugin("honeypot")
        p_ipb = get_plugin("ipban")
        
        plugins_list = [p for p in [p_f2b, p_hp, p_ipb] if p is not None]

        for p in plugins_list:
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            st_txt = "вкл" if s.get("enabled") else "выкл"
            security_p_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st_txt:>4}{NC}")

        panel("Безопасность", [
            f"  {BOLD}Плагины безопасности:{NC}",
            *security_p_lines
        ])

        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(plugins_list, 1):
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}✓{NC}" if s.get("running") else (f"{YELLOW}⚠{NC}" if s.get("installed") else f"{RED}✗{NC}")
            opts.append((str(i),
                         f"{ico} {p.meta.name}",
                         f"{p.meta.description}"))
        
        opts += [
            ("-", "", ""),
            ("A", "✅ Включить всё", "Fail2ban + Honeypot + IPBan"),
            ("B", "❌ Выключить всё", ""),
            ("0", "↩ Назад", "")
        ]

        choice = menu(opts, "БЕЗОПАСНОСТЬ")
        if choice == "0":
            return
        elif choice == "A":
            errors = []
            for p in plugins_list:
                try:
                    _toggle_security_plugin(state, p.meta.name, force_enable=True)
                except Exception as e:
                    errors.append(f"{p.meta.name}: {e}")
            if errors:
                from hydra.ui.tui import warn
                for err in errors:
                    warn(err)
                success("Часть служб безопасности включена (см. ошибки выше)")
            else:
                success("Все службы безопасности включены")
            prompt("Нажмите Enter")
        elif choice == "B":
            errors = []
            for p in plugins_list:
                try:
                    _toggle_security_plugin(state, p.meta.name, force_enable=False)
                except Exception as exc:
                    errors.append(f"{p.meta.name}: {exc}")
            if errors:
                for err in errors:
                    warn(err)
                warn("Часть служб безопасности не удалось выключить")
            else:
                success("Все службы безопасности выключены")
            prompt("Нажмите Enter")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(plugins_list):
                    p = plugins_list[idx]
                    menu_plugin(state, p)
            except ValueError:
                pass


def _toggle_security_plugin(state: AppState, name: str, force_enable: bool | None = None):
    """Toggle a security plugin through the transactional orchestrator."""
    from hydra.plugins.registry import get as get_plugin
    p = get_plugin(name)
    if not p:
        return

    proto = get_protocol(state, name)
    if force_enable is True:
        target_enable = True
    elif force_enable is False:
        target_enable = False
    else:
        target_enable = not (proto and proto.enabled)

    if target_enable:
        if proto and not proto.installed:
            ok = orchestrator.install_plugin(state, name)
            if not ok:
                raise RuntimeError(f"Не удалось установить плагин {name}")
        if not orchestrator.enable(state, name):
            raise RuntimeError(f"Не удалось включить плагин {name}")
    else:
        if not orchestrator.disable(state, name):
            raise RuntimeError(f"Не удалось выключить плагин {name}")


def _menu_amneziawg(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        try:
            st = p.status()
            profiles = p.get_profiles(state) if st.installed else []
            details = [("Профили", len(profiles))]
            details.extend(
                ("", f"{prof['label']} · {prof['interface']} · :{prof['port']} · {prof['preset']}")
                for prof in profiles
            )
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "👤 Профили AWG", "Управление профилями (Desktop/Mobile)"))
                options.append(("4", "🔄 Ротация обфускации", "Ротировать параметры обфускации без downtime"))
                options.append(("5", "⚙️ Оптимизация VPS", "Hardware-aware sysctl/swap/NIC автотюнинг"))
                options.append(("6", "🎲 Генератор обфускации", "Пошаговый мастер генерации обфускации"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text())
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text())
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text())
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _manage_awg_profiles(state, p)
            
        elif choice == "4" and ps.installed and ps.enabled:
            _rotate_awg_obfuscation(state, p)
            
        elif choice == "5" and ps.installed and ps.enabled:
            _tune_awg_hardware(state, p)
            
        elif choice == "6" and ps.installed and ps.enabled:
            _awg_generate_wizard_menu(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AmneziaWG?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")


def _manage_awg_profiles(state: AppState, p):
    while True:
        clear()
        profiles = p.get_profiles(state)
        lines = []
        for i, prof in enumerate(profiles, 1):
            lines.append(f"  {i}. {prof['label']} ({prof['interface']}) on port {prof['port']}")
            lines.append(f"     Preset: {prof['preset']}")
            lines.append(f"     Network: {prof['network']}")
        panel("📁 УПРАВЛЕНИЕ ПРОФИЛЯМИ AWG", lines)
        
        options = []
        has_mobile = any(prof["name"] == "mobile" for prof in profiles)
        if not has_mobile:
            options.append(("1", "➕ Добавить мобильный профиль", "Создать профиль с мобильным пресетом"))
        else:
            options.append(("2", "❌ Удалить мобильный профиль", "Удалить профиль с мобильным пресетом"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "AWG PROFILES")
        if choice == "0":
            break
            
        elif choice == "1" and not has_mobile:
            res = _awg_generate_wizard(state, p)
            if res:
                strategy, carrier = res
                carrier_str = carrier if carrier else "generic"
                preset_name = f"{strategy}:{carrier_str}"
                info(f"Создание профиля с пресетом {preset_name}...")
                if p.add_profile("mobile", preset_name, state):
                    success("Мобильный профиль успешно создан!")
                else:
                    error("Не удалось создать мобильный профиль")
                prompt("Нажмите Enter")
                
        elif choice == "2" and has_mobile:
            if confirm("Удалить мобильный профиль?", default=False):
                info("Удаление...")
                if p.remove_profile("mobile", state):
                    success("Профиль удален")
                else:
                    error("Ошибка удаления")
                prompt("Нажмите Enter")


def _rotate_awg_obfuscation(state: AppState, p):
    profiles = p.get_profiles(state)
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Ротировать {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "РОТАЦИЯ ОБФУСКАЦИИ")
    if choice == "0" or not choice.isdigit():
        return
        
    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]
        
        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if p.rotate_obfuscation(state, profile=prof["name"], preset=preset_name):
                success("Параметры успешно ротированы без downtime!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error("Ошибка ротации")
            prompt("Нажмите Enter")


def _tune_awg_hardware(state: AppState, p):
    info("Анализ и оптимизация VPS...")
    from hydra.plugins.amneziawg.tuning import hw_tune_all
    report = hw_tune_all()
    
    lines = []
    
    # sysctl
    sysctl_changed = sum(1 for v in report["sysctl"].values() if v.get("changed"))
    lines.append("🎛️  Параметры sysctl:")
    if sysctl_changed:
        lines.append(f"     Применено {sysctl_changed} новых оптимизаций.")
    else:
        lines.append("     Все параметры sysctl уже оптимальны.")
        
    # swap
    swap = report["swap"]
    lines.append("💾  Файл подкачки (Swap):")
    if swap["changed"]:
        lines.append(f"     Создан /swapfile размером {swap['target_swap_mb']}M.")
    else:
        lines.append(f"     Текущий swap ({swap['current_swap_mb']}M) достаточен.")
        
    # nic
    nic = report["nic"]
    lines.append("🔌  Сетевой интерфейс:")
    if nic["changed"]:
        lines.append(f"     Включены offloads {nic['changed']} на {nic['iface']}.")
    elif nic["skipped"]:
        lines.append(f"     Пропущено: {nic['skipped']}.")
        
    panel("✅ VPS TUNING REPORT", lines)
    prompt("Нажмите Enter")


def _menu_mieru(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Статус
        try:
            st = p.status()
            current_preset = p.get_current_preset(state)
            
            details = [("Обфускация", f"{BOLD}{CYAN}{current_preset}{NC}")]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "🔒 Обфускация трафика", f"Текущий пресет: {current_preset}"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text())
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text())
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text())
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _menu_mieru_obfuscation(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить Mieru?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return


def _menu_mieru_obfuscation(state: AppState, p):
    from hydra.plugins.mieru.presets import list_presets
    
    while True:
        clear()
        current_preset = p.get_current_preset(state)
        presets = list_presets()
        
        lines = [
            f"Текущий пресет обфускации: {BOLD}{CYAN}{current_preset}{NC}",
            "",
            "Смена пресета перегенерирует конфигурацию sing-box.",
            "Клиенты получат новые настройки при обновлении подписки.",
        ]
        panel("🔒 ОБФУСКАЦИЯ ТРАФИКА MIERU", lines)
        print()
        
        options = []
        for idx, pr in enumerate(presets, 1):
            marker = "  "
            if pr["name"] == current_preset:
                marker = "• "
            options.append((str(idx), f"{marker}{pr['label']}", pr["description"]))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ОБФУСКАЦИЯ MIERU")
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                preset_name = presets[idx]["name"]
                info(f"Применяю пресет обфускации {preset_name}...")
                if p.set_preset(state, preset_name):
                    success(f"Пресет {preset_name} успешно применён!")
                else:
                    error(_apply_error_text("Не удалось применить пресет"))
                prompt("Нажмите Enter")


def _menu_anytls(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Статус
        try:
            st = p.status()
            current_preset = p.get_current_preset(state)
            from hydra.plugins.anytls.presets import get_preset
            preset_label = get_preset(current_preset)["label"]
            
            details = [("Обфускация", f"{BOLD}{CYAN}{preset_label}{NC}")]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "🔒 Обфускация трафика", f"Текущий режим: {preset_label}"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text())
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text())
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text())
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _menu_anytls_obfuscation(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AnyTLS?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return


def _menu_anytls_obfuscation(state: AppState, p):
    from hydra.plugins.anytls.presets import list_presets, get_preset
    
    while True:
        clear()
        current_preset = p.get_current_preset(state)
        presets = list_presets()
        preset_label = get_preset(current_preset)["label"]
        
        lines = [
            f"Текущий режим обфускации: {BOLD}{CYAN}{preset_label}{NC}",
            "",
            "Смена режима перегенерирует конфигурацию sing-box.",
            "Клиенты получат новые настройки при подключении/обновлении.",
        ]
        panel("🔒 ОБФУСКАЦИЯ ТРАФИКА ANYTLS", lines)
        print()
        
        options = []
        for idx, pr in enumerate(presets, 1):
            marker = "  "
            if pr["name"] == current_preset:
                marker = "• "
            options.append((str(idx), f"{marker}{pr['label']}", pr["description"]))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ОБФУСКАЦИЯ ANYTLS")
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                preset_name = presets[idx]["name"]
                info(f"Применяю пресет обфускации {preset_name}...")
                if p.set_preset(state, preset_name):
                    success(f"Пресет {preset_name} успешно применён!")
                else:
                    error(_apply_error_text("Не удалось применить пресет"))
                prompt("Нажмите Enter")


def _menu_trusttunnel(state: AppState, p):
    """Подменю управления TrustTunnel."""
    from hydra.core.state import get_protocol

    while True:
        clear()
        ps = get_protocol(state, p.meta.name)

        try:
            st = p.status()
            domain = ps.config.get("domain", "") if ps.config else ""
            transport = ps.config.get("transport", "tcp") if ps.config else "tcp"
            transport_labels = {
                "tcp": "HTTP/2 TCP",
                "quic": "QUIC UDP",
                "both": "HTTP/2 + QUIC",
            }
            details = [
                ("Домен", domain),
                ("Транспорт", transport_labels.get(transport, "HTTP/2 TCP")),
            ]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )

        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))

            options.append(("3", "🌐 Транспорт", "HTTP/2 TCP / QUIC UDP / оба"))
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, protocol_menu_title(p.meta.name))

        if choice == "0":
            break

        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error(_apply_error_text())
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error(_apply_error_text())
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error(_apply_error_text())
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")

        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")

        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить TrustTunnel?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return

        elif choice == "3" and ps.installed:
            current = ps.config.get("transport", "tcp")
            mode_choice = menu([
                ("1", "HTTP/2 TCP", "Стабильный режим по умолчанию"),
                ("2", "QUIC UDP", "Экспериментальный HTTP/3 через Caddy UDP proxy"),
                ("3", "HTTP/2 + QUIC", "Две клиентские ссылки"),
                ("0", "Отмена", "Оставить текущий режим"),
            ], "ТРАНСПОРТ TRUSTTUNNEL")
            selected = {"1": "tcp", "2": "quic", "3": "both"}.get(mode_choice)
            if selected is not None:
                if selected == current:
                    info("Этот транспорт уже выбран")
                elif p.set_transport(state, selected):
                    success("Транспорт изменён")
                else:
                    error(
                        "Не удалось применить транспорт. Проверьте конфликт UDP/443, "
                        "сертификат и журнал sing-box; прежняя конфигурация восстановлена."
                    )
                prompt("Нажмите Enter")








def _awg_generate_wizard_menu(state: AppState, p):
    profiles = p.get_profiles(state)
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Применить к {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ ГЕНЕРАЦИИ")
    if choice == "0" or not choice.isdigit():
        return
        
    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]
        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if p.rotate_obfuscation(state, profile=prof["name"], preset=preset_name):
                success("Параметры успешно применены!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error(_apply_error_text("Ошибка применения параметров"))
            prompt("Нажмите Enter")


def _awg_generate_wizard(state: AppState, p) -> tuple[str, str | None] | None:
    from hydra.plugins.amneziawg.presets import list_strategies, list_carriers, generate_params, STRATEGIES, CARRIER_OVERRIDES

    # Step 1: Select Strategy
    strategies = list_strategies()
    strat_opts = []
    for idx, s in enumerate(strategies, 1):
        strat_opts.append((str(idx), s["label"], s["description"]))
    strat_opts.append(("0", "Отмена", ""))
    
    choice = menu(strat_opts, "ШАГ 1: ВЫБЕРИТЕ СТРАТЕГИЮ (ТИП СЕТИ)")
    if choice == "0" or not choice.isdigit():
        return None
        
    s_idx = int(choice) - 1
    if not (0 <= s_idx < len(strategies)):
        return None
        
    strategy = strategies[s_idx]["name"]
    carrier = None
    
    # Step 2: Select Carrier if mobile
    if strategy == "mobile":
        carriers = list_carriers(strategy)
        carrier_opts = []
        for idx, c in enumerate(carriers, 1):
            carrier_opts.append((str(idx), c["label"], c["description"]))
        carrier_opts.append(("0", "Отмена", ""))
        
        c_choice = menu(carrier_opts, "ШАГ 2: ВЫБЕРИТЕ ОПЕРАТОРА СВЯЗИ")
        if c_choice == "0" or not c_choice.isdigit():
            return None
            
        c_idx = int(c_choice) - 1
        if not (0 <= c_idx < len(carriers)):
            return None
            
        carrier = carriers[c_idx]["name"]
        if carrier == "generic":
            carrier = None

    # Step 3: Loop for Preview & Regeneration
    while True:
        params = generate_params(strategy=strategy, carrier=carrier)
        
        strat_label = STRATEGIES[strategy].label
        carrier_label = "Универсальный мобильный"
        if carrier:
            carrier_label = CARRIER_OVERRIDES[carrier].label
        elif strategy != "mobile":
            carrier_label = "Не требуется (проводной/stealth)"
            
        lines = [
            f"  Стратегия:  {strat_label}",
            f"  Оператор:   {carrier_label}",
            "",
            f"  Jc   = {params['Jc']:<6}  S1 = {params['S1']:<6}  H1 = {params['H1']}",
            f"  Jmin = {params['Jmin']:<6}  S2 = {params['S2']:<6}  H2 = {params['H2']}",
            f"  Jmax = {params['Jmax']:<6}  S3 = {params['S3']:<6}  H3 = {params['H3']}",
            f"                  S4 = {params['S4']:<6}  H4 = {params['H4']}",
            "",
            f"  I1   = {params['I1'] if params['I1'] else 'Отсутствует'}",
            "",
            f"  {GREEN}ⓘ{NC}  S1({params['S1']}) + 56 = {int(params['S1'])+56} != S2({params['S2']}) — сигнатура WireGuard устранена",
            f"  {GREEN}ⓘ{NC}  Заголовки H1-H4 полностью уникальны и рандомизированы",
        ]
        
        clear()
        panel("🎲 СГЕНЕРИРОВАННЫЕ ПАРАМЕТРЫ ОБФУСКАЦИИ", lines)
        
        confirm_opts = [
            ("1", "✅ Применить эти параметры", "Сохранить и перезапустить туннель с ними"),
            ("2", "🔄 Перегенерировать", "Сгенерировать другие случайные значения"),
            ("0", "❌ Отмена", "Выйти без сохранения"),
        ]
        
        ans = menu(confirm_opts, "ПОДТВЕРЖДЕНИЕ ГЕНЕРАЦИИ")
        if ans == "1":
            return strategy, carrier
        elif ans == "2":
            continue
        else:
            return None
