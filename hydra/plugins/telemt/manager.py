"""
hydra/plugins/telemt/manager.py — TUI-консоль управления Telemt MTProxy.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import urllib.request
import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from hydra.core.state import AppState, save_state
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA, BOLD, DIM, WHITE, NC
)
import hydra.core.orchestrator as orchestrator

from hydra.plugins.telemt.plugin import (
    BIN_PATH, CONFIG_DIR, CONFIG_FILE, WORK_DIR, SERVICE_FILE, LOG_FILE,
    SERVICE_NAME, DEFAULT_PORT
)
from hydra.plugins.telemt.tg_nets import (
    get_tg_nets, update_tg_nets_interactive, tg_nets_status_line
)

class _Cancelled(Exception):
    pass

# ══════════════════════════════════════════════════════════════════════════════
#  ЛАЙЗИ-ИМПОРТЫ
# ══════════════════════════════════════════════════════════════════════════════
def _get_fallback_module():
    try:
        from hydra.plugins.telemt import telemt_fallback as fb
        return fb
    except ImportError:
        return None

def _get_syn_limiter_module():
    try:
        from hydra.plugins.telemt import telemt_syn_limiter as sl
        return sl
    except ImportError:
        return None

def _get_ios_fix_module():
    try:
        from hydra.plugins.telemt import telemt_ios_fix as i_fix
        return i_fix
    except ImportError:
        return None

def _get_mss_module():
    try:
        from hydra.plugins.telemt import telemt_mss_selector as mss
        return mss
    except ImportError:
        return None

def _get_self_route_module():
    try:
        from hydra.plugins.telemt import telemt_self_route as sr
        return sr
    except ImportError:
        return None

def _get_stats_module():
    try:
        from hydra.plugins.telemt import mtproto_stats as st
        return st
    except ImportError:
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd: list, capture: bool = False) -> subprocess.CompletedProcess:
    kw = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _get_installed_version() -> Optional[str]:
    if not BIN_PATH.exists():
        return None
    r = _run([str(BIN_PATH), "--version"], capture=True)
    m = re.search(r'(\d+\.\d+[\.\d]*)', r.stdout + r.stderr)
    return m.group(1) if m else "unknown"

def _get_public_ip() -> tuple[str, str]:
    ipv4 = ""
    # Пытаемся получить IP через api.ipify.org
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                ipv4 = r.read().decode().strip()
            if ipv4:
                break
        except Exception:
            pass
    
    # Fallback: парсим ip route
    if not ipv4:
        try:
            out = _run(["ip", "route", "get", "8.8.8.8"], capture=True).stdout
            m = re.search(r'src\s+([\d.]+)', out)
            if m:
                ipv4 = m.group(1)
        except Exception:
            pass

    ipv6 = ""
    try:
        req = urllib.request.Request("https://api6.ipify.org", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            ipv6 = r.read().decode().strip()
    except Exception:
        pass

    return ipv4, ipv6

def _pause() -> None:
    print(f"\n  {DIM}Нажмите Enter для продолжения...{NC}", end="", flush=True)
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()

def _ask(label: str, default: str = "", required: bool = False) -> str:
    try:
        val = prompt(label, default=default).strip()
        if required and not val:
            raise _Cancelled()
        return val
    except KeyboardInterrupt:
        print()
        raise _Cancelled()

def _make_tls_secret(base_secret: str, domain: str) -> str:
    return f"ee{base_secret}{domain.encode().hex()}"

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ И УПРАВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def menu_telemt(state: AppState, plugin) -> None:
    # Инициализируем настройки в state.json
    ps = state.protocols.setdefault("telemt", state.protocols.get("telemt") or __import__("hydra.core.state").core.state.PluginState())
    if not ps.config:
        ps.config = {
            "port": DEFAULT_PORT,
            "tls_domain": state.network.domain or "google.com",
            "client_mss": "",
            "use_middle_proxy": False,
            "fallback_cfg": None,
            "singbox_integration_enabled": False,
            "singbox_integration_port": 10811,
            "syn_limiter_enabled": False,
            "ios_fix_enabled": False,
        }

    while True:
        clear()
        
        # Статус службы
        installed = plugin._installed()
        r = _run(["systemctl", "is-active", SERVICE_NAME], capture=True)
        is_active = r.stdout.strip() == "active"
        ver = _get_installed_version() if installed else None
        
        svc_str = (
            f"{GREEN}● запущен   {ver or ''}{NC}" if is_active else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        status_lines = [
            f"  Статус:      {svc_str}",
            f"  Порт:        {ps.config.get('port', DEFAULT_PORT)}",
            f"  Домен (TLS): {ps.config.get('tls_domain', '—')}",
        ]

        # Статус интеграции с Sing-Box
        sb_int = ps.config.get("singbox_integration_enabled", False)
        sb_port = ps.config.get("singbox_integration_port", 10811)
        sr_mod = _get_self_route_module()
        sr_status = sr_mod.status() if (sr_mod and installed) else {"return_rule": False, "after_xray": False}
        
        if sb_int:
            route_status = f"{GREEN}активна (redirect :{sb_port}){NC}"
            if sr_status.get("return_rule") and sr_status.get("after_xray"):
                route_status += f"  {GREEN}[rule: OK]{NC}"
            else:
                route_status += f"  {YELLOW}[rule: нет]{NC}"
            status_lines.append(f"  Sing-Box:    {route_status}")
        else:
            status_lines.append(f"  Sing-Box:    {DIM}выключена (direct){NC}")

        # Статус подсетей Telegram
        status_lines.append(f"  Подсети TG:  {tg_nets_status_line()}")

        # Статус fallback
        fb_mod = _get_fallback_module()
        if fb_mod and CONFIG_FILE.exists():
            status_lines.append(f"  Fallback:    {fb_mod.fallback_status_line(CONFIG_FILE)}")

        # Статус SYN-лимитера
        sl_mod = _get_syn_limiter_module()
        if sl_mod and CONFIG_FILE.exists():
            status_lines.append(f"  SYN-limiter: {sl_mod.syn_limiter_status_line()}")

        # iOS-фикс
        if_mod = _get_ios_fix_module()
        if if_mod and CONFIG_FILE.exists():
            status_lines.append(f"  iOS-фикс:    {if_mod.ios_fix_status_line()}")
            
        status_lines.append(f"  Автор:       {DIM}gr33nimax{NC}")

        panel("🛡️ TELEMT CONTROL PANEL", status_lines)

        opts = [
            ("1", "🚀  Установить / Переустановить", "Интерактивная настройка с нуля"),
            ("2", "👥  Просмотр пользователей и ссылок", "Показать учетные записи и ссылки для подключения"),
            ("3", "🔄  Перезапустить сервис", "Сброс службы telemt"),
            ("4", "⬆️   Проверить и обновить бинарник", "Обновление telemt до последней версии с GitHub"),
            ("5", "📊  Статистика трафика", "Просмотр статистики по сессиям и байтам"),
            ("6", "📋  Статус службы / журналы логов", "Журналы systemd и stdout"),
            ("X", "🌐  Sing-Box-интеграция (обход блоков)", "Заворот Telegram трафика в Sing-Box/WARP"),
            ("F", "🔀  Hybrid Fallback (Middle ↔ Direct)", "Параметры резервирования связи"),
            ("S", "🛡️   SYN-limiter (защита от флуда)", "Ограничение скорости SYN-пакетов"),
            ("I", "🍎  iOS-фикс (MSS + порт)", "Обход блокировок на Apple устройствах"),
            ("N", "🌐  Обновить подсети Telegram (RIPE)", "Загрузить свежие диапазоны IP Telegram"),
            ("8", f"{RED}🗑️   Полное удаление{NC}", "Удалить сервис, правила фаервола и бинарник"),
            ("-", "", ""),
            ("0", "↩ Назад в главное меню", "")
        ]

        choice = menu(opts, "ВЫБЕРИТЕ ОПЦИЮ")
        
        try:
            if choice == "0":
                break
            
            elif choice == "1":
                _run_install(state, plugin)
                
            elif choice == "2":
                _view_links(state)
                
            elif choice == "3":
                info("Перезапускаю telemt...")
                _run(["systemctl", "restart", SERVICE_NAME])
                success("Служба перезапущена.")
                _pause()
                
            elif choice == "4":
                _run_update(plugin)
                
            elif choice == "5":
                st_mod = _get_stats_module()
                if st_mod:
                    st_mod.stats_menu()
                else:
                    error("Модуль статистики mtproto_stats недоступен.")
                    _pause()
                    
            elif choice == "6":
                _view_logs()
                
            elif choice == "8":
                if confirm("Вы уверены, что хотите полностью удалить Telemt?"):
                    _run_uninstall(state, plugin)
                    _pause()
                    
            elif choice == "x":
                _menu_singbox_integration(state, plugin)
                
            elif choice == "f":
                _menu_fallback(state, plugin)
                
            elif choice == "s":
                _menu_syn_limiter()
                
            elif choice == "i":
                _menu_ios_fix()
                
            elif choice == "n":
                _menu_update_tg_nets(state, plugin)

        except _Cancelled:
            info("Операция отменена.")
            _pause()
        except Exception as e:
            error(f"Неожиданная ошибка: {e}")
            _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕРАКТИВНАЯ УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install(state: AppState, plugin) -> None:
    clear()
    warn("Начинаю установку / настройку Telemt MTProxy...")

    server_ip, server_ipv6 = _get_public_ip()

    # 1. Выбор IPv4 / IPv6 / DualStack
    proto_choice = menu([
        ("1", "Только IPv4", ""),
        ("2", "Только IPv6", ""),
        ("3", "DualStack IPv4+IPv6 (Рекомендуется)", "")
    ], "ВЫБЕРИТЕ СЕТЕВОЙ ПРОТОКОЛ")
    
    ipv4 = proto_choice in ("1", "3")
    ipv6 = proto_choice in ("2", "3")

    # 2. Выбор порта
    port_choice = menu([
        ("1", "Стандартный 8443 (Рекомендуется)", ""),
        ("2", "443 (под вид веб-трафика)", ""),
        ("3", "Ввести свой порт вручную", "")
    ], "ВЫБЕРИТЕ ПОРТ ПРОКСИ")
    
    port = 8443
    if port_choice == "2":
        port = 443
    elif port_choice == "3":
        while True:
            try:
                p_str = _ask("Введите порт (1024-65535)")
                port = int(p_str)
                if 1024 <= port <= 65535:
                    break
                error("Неверный диапазон порта.")
            except (ValueError, _Cancelled):
                return

    # 3. Выбор TLS домена
    tls_domain = _ask("Введите домен маскировки TLS (например, google.com)", default=state.network.domain or "google.com")

    # 4. Выбор MSS фрагментации (anti-JA4 ТСПУ)
    client_mss = ""
    mss_mod = _get_mss_module()
    if mss_mod:
        try:
            client_mss = mss_mod.mss_select_interactive()
        except _Cancelled:
            return

    # 5. Регион сервера: Direct vs Middle Proxy
    region_choice = menu([
        ("1", "Да, Telegram заблокирован (РФ / NAT) -> Direct Mode", ""),
        ("2", "Нет, Telegram доступен напрямую -> Middle Proxy", "")
    ], "ЗАБЛОКИРОВАН ЛИ TELEGRAM НА ЭТОМ СЕРВЕРЕ?")
    
    use_mp = (region_choice == "2")

    # 6. Fallback (если Middle Proxy)
    fb_cfg = None
    if use_mp:
        fb_mod = _get_fallback_module()
        if fb_mod:
            if confirm("Настроить автоматический fallback на Direct Mode при сбое Middle Proxy?"):
                fb_cfg = fb_mod.me_probe_menu(CONFIG_FILE)
            else:
                fb_cfg = fb_mod.FallbackConfig.defaults()

    # 7. Интеграция с Sing-Box
    sb_int = False
    if confirm("Направить исходящий трафик Telemt через Sing-Box (нужно для WARP in РФ)?"):
        sb_int = True

    # Применяем настройки в state
    ps = state.protocols["telemt"]
    ps.config["port"] = port
    ps.config["tls_domain"] = tls_domain
    ps.config["client_mss"] = client_mss
    ps.config["use_middle_proxy"] = use_mp
    ps.config["fallback_cfg"] = asdict(fb_cfg) if fb_cfg else None
    ps.config["singbox_integration_enabled"] = sb_int
    ps.installed = True
    ps.enabled = True
    save_state(state)

    info("Скачиваю зависимости и бинарник telemt...")
    if not plugin.install():
        error("Установка бинарника провалилась.")
        _pause()
        return

    info("Записываю конфигурационные файлы...")
    plugin.configure(state)
    plugin.apply(state)
    if orchestrator.apply_config(state):
        success("Установка успешно завершена!")
        # Дополнительно: оптимизация ядра sysctl
        _apply_optimizations()
    else:
        error("Ошибка применения конфигурации Sing-Box / Telemt.")
    
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ (ПОДМЕНЮ)
# ══════════════════════════════════════════════════════════════════════════════
def _view_links(state: AppState) -> None:
    clear()
    ps = state.protocols["telemt"]
    port = ps.config.get("port", DEFAULT_PORT)
    domain = ps.config.get("tls_domain", "google.com")
    server_ip, _ = _get_public_ip()

    if not state.users:
        warn("Нет активных пользователей в системе. Создайте пользователя в меню 'Пользователи'.")
        _pause()
        return

    # iOS-фикс статус
    if_mod = _get_ios_fix_module()
    ios_st = if_mod.status() if if_mod else {"enabled": False}

    lines = []
    for u in state.users:
        if u.blocked:
            continue
        # Импортируем TelemtPlugin динамически для derive методов
        from hydra.plugins.telemt.plugin import TelemtPlugin
        secret = TelemtPlugin._derive_secret(u.uuid)
        username = TelemtPlugin._derive_username(u.uuid)
        
        tls_secret = _make_tls_secret(secret, domain) if domain else secret
        link = f"tg://proxy?server={server_ip}&port={port}&secret={tls_secret}"
        
        lines.append(f"{BOLD}{u.email}{NC} (username: {username})")
        lines.append(f"  {YELLOW}{link}{NC}")
        
        if ios_st.get("enabled"):
            ios_link = f"tg://proxy?server={server_ip}&port={ios_st['ext_port']}&secret={tls_secret}"
            lines.append(f"  {DIM}└─ iOS:{NC} {CYAN}{ios_link}{NC}")
        lines.append("")

    panel("🔗 ССЫЛКИ ДЛЯ ПОДКЛЮЧЕНИЯ TELEGRAM", lines)
    _pause()

def _run_update(plugin) -> None:
    clear()
    info("Проверяю обновления Telemt...")
    from hydra.plugins.telemt.plugin import GITHUB_REPO
    from hydra.utils.downloader import latest_release
    
    current = _get_installed_version() or "unknown"
    latest = latest_release(GITHUB_REPO)
    
    print(f"  Установленная версия: {current}")
    print(f"  Последняя на GitHub:  {latest}")
    print()
    
    if current == latest:
        success("У вас уже установлена последняя версия!")
        _pause()
        return
        
    if confirm(f"Обновить Telemt до версии {latest}?"):
        info("Скачиваю обновление...")
        if plugin._download_binary():
            _run(["systemctl", "restart", SERVICE_NAME])
            success("Telemt успешно обновлен!")
        else:
            error("Обновление завершилось с ошибкой.")
        _pause()

def _view_logs() -> None:
    clear()
    panel("СТАТУС СЛУЖБЫ TELEMT", [])
    r1 = subprocess.run(["systemctl", "status", SERVICE_NAME, "--no-pager"], capture_output=True, text=True)
    print(r1.stdout or r1.stderr)
    
    print(f"\n{BOLD}{CYAN}Последние 25 строк логов:{NC}")
    r2 = subprocess.run(["journalctl", "-u", SERVICE_NAME, "-n", "25", "--no-pager"], capture_output=True, text=True)
    print(r2.stdout or r2.stderr)
    _pause()

def _menu_singbox_integration(state: AppState, plugin) -> None:
    clear()
    ps = state.protocols["telemt"]
    sb_int = ps.config.get("singbox_integration_enabled", False)
    sb_port = ps.config.get("singbox_integration_port", 10811)

    panel("🌐 ИНТЕГРАЦИЯ С SING-BOX / WARP", [
        f"  Текущий статус: {'🟢 АКТИВНА' if sb_int else '🔴 ОТКЛЮЧЕНА (direct)'}",
        f"  Порт перехвата: {sb_port}",
        "",
        "  При включении трафик Telemt к подсетям Telegram перенаправляется",
        "  в Sing-Box (порт redirect) и уходит через WARP (если он включен).",
    ])

    choice = menu([
        ("1", f"{'⏸️  Отключить' if sb_int else '▶️  Включить'} интеграцию с Sing-Box", ""),
        ("2", "⚙️  Изменить порт перехвата Sing-Box", ""),
        ("0", "↩ Назад", "")
    ], "НАСТРОЙКА SING-BOX CASCADE")

    if choice == "1":
        ps.config["singbox_integration_enabled"] = not sb_int
        save_state(state)
        info("Применяю изменения...")
        plugin.configure(state)
        plugin.apply(state)
        if orchestrator.apply_config(state):
            success("Конфигурация обновлена!")
        else:
            error("Не удалось применить конфигурацию.")
        _pause()
        
    elif choice == "2":
        try:
            p_str = _ask("Введите порт перехвата redirect (например, 10811)")
            p = int(p_str)
            if 1024 <= p <= 65535:
                ps.config["singbox_integration_port"] = p
                save_state(state)
                info("Применяю изменения...")
                plugin.configure(state)
                plugin.apply(state)
                if orchestrator.apply_config(state):
                    success("Порт перехвата обновлен!")
                else:
                    error("Не удалось применить конфигурацию.")
            else:
                error("Неверный порт.")
            _pause()
        except (ValueError, _Cancelled):
            pass

def _menu_fallback(state: AppState, plugin) -> None:
    fb_mod = _get_fallback_module()
    if not fb_mod:
        error("Модуль fallback недоступен.")
        _pause()
        return

    while True:
        clear()
        ps = state.protocols["telemt"]
        use_mp = ps.config.get("use_middle_proxy", False)
        fb_cfg_dict = ps.config.get("fallback_cfg")
        
        # Читаем реальный статус из конфига
        mp_now = fb_mod.read_runtime_middle_proxy(CONFIG_FILE) if CONFIG_FILE.exists() else False

        lines = [
            f"  Использовать Middle Proxy: {'да' if use_mp else 'нет'}",
            f"  Текущий рантайм-режим:    {'Middle Proxy' if mp_now else 'Direct Mode'}",
        ]
        
        if fb_cfg_dict:
            lines.append(f"  Авто-fallback к Direct:    {fb_cfg_dict.get('fallback_to_direct')}")
            lines.append(f"  Попыток до fallback:       {fb_cfg_dict.get('fallback_after_attempts')}")
            lines.append(f"  Таймаут проверки (сек):     {fb_cfg_dict.get('fallback_after_seconds')}")
        else:
            lines.append("  Авто-fallback:             не настроен")

        panel("🔀 HYBRID FALLBACK CONTROL", lines)

        choice = menu([
            ("1", "⚙️  Изменить параметры fallback и режим", ""),
            ("2", "🔍  Проверить доступность ME-серверов сейчас", ""),
            ("3", "▶️   Применить Direct Mode вручную (runtime)", ""),
            ("4", "◀️   Применить Middle Proxy вручную (runtime)", ""),
            ("0", "↩ Назад", "")
        ], "FALLBACK МЕНЮ")

        if choice == "0":
            break
            
        elif choice == "1":
            # Выбор использования Middle Proxy
            use_mp_ans = confirm("Использовать Middle Proxy по умолчанию?")
            state.protocols["telemt"].config["use_middle_proxy"] = use_mp_ans
            
            fb_cfg = None
            if use_mp_ans:
                if confirm("Настроить автоматический fallback на Direct?"):
                    fb_cfg = fb_mod.me_probe_menu(CONFIG_FILE)
                    state.protocols["telemt"].config["fallback_cfg"] = asdict(fb_cfg)
                else:
                    state.protocols["telemt"].config["fallback_cfg"] = asdict(fb_mod.FallbackConfig.defaults())
            else:
                state.protocols["telemt"].config["fallback_cfg"] = None
                
            save_state(state)
            info("Перезаписываю конфигурацию...")
            plugin.configure(state)
            plugin.apply(state)
            if orchestrator.apply_config(state):
                success("Настройки успешно изменены!")
            else:
                error("Ошибка применения конфигурации.")
            _pause()
            
        elif choice == "2":
            print()
            info("Проверяю доступность ME-серверов Telegram...")
            live = fb_mod.fetch_live_me_endpoints()
            src = f"живой пул getProxyConfig ({len(live)} адресов)" if live else "статический fallback-список"
            info(f"Источник: {src}")
            probe = fb_mod.MiddleProxyProbe(live or fb_mod._ME_ENDPOINTS)
            ok_c, total_c = probe.probe_all()
            ratio = ok_c / total_c if total_c else 0
            if ratio >= fb_mod._ME_QUORUM:
                success(f"ME-серверы доступны: {ok_c}/{total_c} ({ratio:.0%})")
            else:
                warn(f"ME-серверы недоступны: {ok_c}/{total_c} ({ratio:.0%} < кворум {fb_mod._ME_QUORUM:.0%})")
            _pause()
            
        elif choice == "3":
            info("Переключаю в Direct Mode (runtime)...")
            if fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=False):
                applied, method = fb_mod.apply_telemt_reload(SERVICE_NAME)
                if applied:
                    success(f"Успешно переключено в Direct Mode через {method}.")
                else:
                    error("Не удалось применить изменения к telemt.")
            else:
                error("Не удалось записать конфигурационный файл.")
            _pause()
            
        elif choice == "4":
            info("Переключаю в Middle Proxy (runtime)...")
            if fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=True):
                applied, method = fb_mod.apply_telemt_reload(SERVICE_NAME)
                if applied:
                    success(f"Успешно переключено в Middle Proxy через {method}.")
                else:
                    error("Не удалось применить изменения к telemt.")
            else:
                error("Не удалось записать конфигурационный файл.")
            _pause()

def _menu_syn_limiter() -> None:
    sl_mod = _get_syn_limiter_module()
    if not sl_mod:
        error("Модуль SYN-лимитера недоступен.")
        _pause()
        return
    try:
        sl_mod.syn_limiter_menu()
    except _Cancelled:
        pass

def _menu_ios_fix() -> None:
    if_mod = _get_ios_fix_module()
    if not if_mod:
        error("Модуль iOS-фикса недоступен.")
        _pause()
        return
    try:
        if_mod.ios_fix_menu()
    except _Cancelled:
        pass

def _menu_update_tg_nets(state: AppState, plugin) -> None:
    clear()
    panel("🌐 ОБНОВЛЕНИЕ ПОДСЕТЕЙ TELEGRAM", [
        "  Источники: RIPE NCC (BGP announced-prefixes)",
        "  ASN: AS62041, AS59930, AS44907, AS211157, AS42065",
        "",
        "  После обновления новые диапазоны IP-адресов будут применены",
        "  в правилах перехвата трафика Sing-Box/iptables.",
    ])

    if confirm("Обновить подсети Telegram сейчас?"):
        new_nets = update_tg_nets_interactive()
        sb_int = state.protocols["telemt"].config.get("singbox_integration_enabled", False)
        
        if sb_int:
            info("Перенастраиваю iptables-перехват...")
            sr_mod = _get_self_route_module()
            if sr_mod:
                # Перезапускаем правила роутинга
                sr_mod.disable()
                # Применение новых правил произойдет при apply() плагина
                plugin.configure(state)
                plugin.apply(state)
                if orchestrator.apply_config(state):
                    success("Диапазоны обновлены и применены к фаерволу!")
                else:
                    error("Не удалось применить конфигурацию.")
            else:
                error("Модуль self-route недоступен.")
        else:
            success("Список обновлен на диске (/etc/telemt/tg_nets.txt).")
            info("Служба Sing-Box интеграции выключена, перезапись фаервола не требуется.")
        _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ДЕИНСТАЛЛЯЦИЯ И СИСТЕМНЫЕ ТЮНИНГИ
# ══════════════════════════════════════════════════════════════════════════════
def _run_uninstall(state: AppState, plugin) -> None:
    info("Удаляю службу Telemt MTProxy...")
    
    # 1. Отключаем self-route
    sr_mod = _get_self_route_module()
    if sr_mod:
        sr_mod.disable()

    # 2. Отключаем iOS-фикс
    if_mod = _get_ios_fix_module()
    if if_mod:
        if_mod.disable_ios_fix()

    # 3. Отключаем SYN-лимитер
    sl_mod = _get_syn_limiter_module()
    if sl_mod:
        sl_mod.disable_syn_limiter()

    # 4. Отключаем iptables-stats
    st_mod = _get_stats_module()
    if st_mod:
        st_mod._reset_accounting()
        
    # Удаляем кронфайл статистики
    CRON_FILE = Path("/etc/cron.d/telemt-stats")
    CRON_FILE.unlink(missing_ok=True)

    # 5. Очищаем sysctl и лимиты
    Path("/etc/sysctl.d/99-telemt-performance.conf").unlink(missing_ok=True)
    Path("/etc/security/limits.d/99-telemt-limits.conf").unlink(missing_ok=True)
    _run(["sysctl", "--system"])

    # 6. Запускаем стандартный uninstall плагина
    if plugin.uninstall():
        ps = state.protocols["telemt"]
        ps.installed = False
        ps.enabled = False
        ps.config = {}
        save_state(state)
        
        # Пересобираем Sing-Box без telemt redirect
        orchestrator.apply_config(state)
        success("Telemt полностью удален с сервера.")
    else:
        error("Ошибка при удалении файлов плагина.")

def _apply_optimizations() -> None:
    """Оптимизация сетевых буферов sysctl и лимитов ulimit для высокой нагрузки."""
    opt_file = Path("/etc/sysctl.d/99-telemt-performance.conf")
    lim_file = Path("/etc/security/limits.d/99-telemt-limits.conf")
    
    try:
        opt_file.write_text(
            "fs.file-max = 2097152\n"
            "net.core.somaxconn = 65535\n"
            "net.ipv4.tcp_max_syn_backlog = 65535\n"
            "net.ipv4.tcp_fin_timeout = 15\n"
            "net.ipv4.tcp_tw_reuse = 1\n"
            "net.ipv4.tcp_rmem = 4096 87380 16777216\n"
            "net.ipv4.tcp_wmem = 4096 65536 16777216\n"
            "net.ipv6.conf.all.disable_ipv6 = 0\n"
        )
        _run(["sysctl", "--system"])
        
        lim_file.write_text(
            "* soft nofile 1048576\n"
            "* hard nofile 1048576\n"
            "root soft nofile 1048576\n"
            "root hard nofile 1048576\n"
        )
    except Exception:
        pass
