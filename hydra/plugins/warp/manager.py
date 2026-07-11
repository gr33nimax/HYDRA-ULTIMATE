"""
hydra/plugins/warp/manager.py — TUI-консоль управления Cloudflare WARP.
"""
from __future__ import annotations

import json
from pathlib import Path
from hydra.core.state import AppState, save_state
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA, BOLD, DIM, WHITE, NC
)
import hydra.core.orchestrator as orchestrator
from hydra.plugins.warp.plugin import DEFAULT_WARP_DOMAINS, WARP_EXTERNAL_CACHE


def _get_external_info() -> tuple[list[str], list[str], str]:
    """Возвращает (domains, ips, updated_at)."""
    if not WARP_EXTERNAL_CACHE.exists():
        return [], [], ""
    try:
        data = json.loads(WARP_EXTERNAL_CACHE.read_text(encoding="utf-8"))
        return data.get("domains", []), data.get("ips", []), data.get("updated_at", "")
    except Exception:
        return [], [], ""


def _get_last_install_error() -> str:
    path = Path("/var/log/hydra/install.log")
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        # Ищем снизу вверх последнюю ошибку
        for line in reversed(lines):
            line_upper = line.upper()
            if "[ERROR]" in line_upper or "CONFIG INVALID" in line_upper or "FAILED" in line_upper:
                return line
    except Exception:
        pass
    return ""


def _show_diagnostic_info():
    print(f"\n  {YELLOW}═══════════════ ДИАГНОСТИКА ОШИБКИ ═══════════════{NC}")
    
    # 1. Проверяем install.log
    install_err = _get_last_install_error()
    if install_err:
        warn("Последняя ошибка из /var/log/hydra/install.log:")
        print(f"  {RED}{install_err}{NC}")
    
    # Показываем отладочный конфиг, если он существует
    debug_path = Path("/var/log/hydra/warp_debug_config.json")
    if debug_path.exists():
        warn("Секции outbounds и route из сгенерированного конфига:")
        try:
            cfg = json.loads(debug_path.read_text(encoding='utf-8'))
            print(f"  {BOLD}outbounds:{NC}")
            print(f"  {DIM}{json.dumps(cfg.get('outbounds', []), indent=2)}{NC}")
            print(f"  {BOLD}route:{NC}")
            print(f"  {DIM}{json.dumps(cfg.get('route', {}), indent=2)}{NC}")
        except Exception as e:
            print(f"  Ошибка чтения конфига: {e}")

    # 2. Проверяем статус sing-box
    import subprocess
    r = subprocess.run(["systemctl", "status", "sing-box"], capture_output=True, text=True)
    if r.returncode != 0:
        warn("Служба sing-box неактивна или сообщает об ошибке.")
    
    # 3. Показываем последние логи sing-box
    r2 = subprocess.run(["journalctl", "-u", "sing-box", "-n", "10", "--no-pager"], capture_output=True, text=True)
    if r2.stdout:
        warn("Последние 10 строк логов sing-box из journalctl:")
        for line in r2.stdout.splitlines():
            print(f"  {DIM}{line}{NC}")
            
    print(f"  {YELLOW}══════════════════════════════════════════════════{NC}\n")


def menu_warp(state: AppState, plugin) -> None:
    ps = state.protocols.setdefault("warp", state.protocols.get("warp") or __import__("hydra.core.state").core.state.PluginState())
    if not ps.config:
        ps.config = {
            "domains": DEFAULT_WARP_DOMAINS.copy(),
            "ips": [],
            "external_url": ""
        }

    while True:
        clear()

        # Получаем актуальный статус
        st = plugin.status()
        
        # Данные из конфига
        domains = ps.config.setdefault("domains", DEFAULT_WARP_DOMAINS.copy())
        ips = ps.config.setdefault("ips", [])
        enabled_lists = ps.config.setdefault("enabled_external_lists", [])

        # Данные из внешнего кэша
        ext_domains, ext_ips, ext_updated = _get_external_info()
        
        # Общие счетчики
        total_domains = len(set(domains + ext_domains))
        total_ips = len(set(ips + ext_ips))

        status_lines = []
        if not st.installed:
            status_lines.append(f"  Статус:      {RED}не установлен{NC}")
        else:
            status_lines.append(f"  Статус:      {(GREEN+'● активен') if st.running else (DIM+'○ остановлен (выключен)')}{NC}")
            status_lines.append(f"  Включён:     {GREEN if st.enabled else DIM}{'да' if st.enabled else 'нет'}{NC}")
            status_lines.append("  " + "─" * 40)
            status_lines.append(f"  Доменов (локальных):     {CYAN}{len(domains)}{NC}")
            status_lines.append(f"  IP/подсетей (локальных):  {CYAN}{len(ips)}{NC}")
            if enabled_lists:
                from hydra.plugins.warp.plugin import EXTERNAL_LISTS
                list_names = [EXTERNAL_LISTS[k]["name"] for k in enabled_lists if k in EXTERNAL_LISTS]
                status_lines.append(f"  Внешние списки:          {GREEN}{', '.join(list_names)}{NC}")
                status_lines.append(f"  Доменов (внешних):       {CYAN}{len(ext_domains)}{NC}")
                status_lines.append(f"  IP/подсетей (внешних):    {CYAN}{len(ext_ips)}{NC}")
                if ext_updated:
                    # Преобразуем ISO дату в более простой вид
                    dt = ext_updated.split(".")[0].replace("T", " ")
                    status_lines.append(f"  Кэш обновлён:            {DIM}{dt}{NC}")
                else:
                    status_lines.append(f"  Кэш обновлён:            {YELLOW}ни разу (требуется загрузка){NC}")
            else:
                status_lines.append(f"  Внешние списки:          {DIM}отключены{NC}")
            
            status_lines.append("  " + "─" * 40)
            status_lines.append(f"  Всего доменов в WARP:    {GREEN}{total_domains}{NC}")
            status_lines.append(f"  Всего IP/подсетей in WARP:{GREEN}{total_ips}{NC}")
            
        panel("🌐 CLOUDFLARE WARP ROUTING", status_lines)

        options = []
        if not st.installed:
            options.append(("1", "🔧 Установить Cloudflare WARP", "Скачать wgcf и сгенерировать профиль"))
        else:
            options.append(("1", f"{'⏸️  Выключить' if st.enabled else '▶️  Включить'} WARP", "Переключить статус службы"))
            options.append(("2", f"📝 Управление доменами ({len(domains)} шт.)", "Просмотр, добавление и удаление доменов"))
            options.append(("3", f"📝 Управление IP/подсетями ({len(ips)} шт.)", "Просмотр, добавление и удаление IP-адресов/CIDR"))
            options.append(("4", "🔗 Настройка внешнего источника", "Задать ссылку на внешний список правил"))
            options.append(("5", "⚙️ Настройка Гео-профилей (релеев)", "Добавить/удалить кастомные WireGuard/AmneziaWG профили"))
            options.append(("-", "", ""))
            options.append(("8", "🔄 Переустановить", "Пересоздать профиль WARP с нуля"))
            options.append(("9", "❌ Удалить", "Полное удаление WARP и профилей с сервера"))
            
        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "УПРАВЛЕНИЕ WARP ROUTING")

        if choice == "0":
            break

        # ── Установка ──
        if choice == "1" and not st.installed:
            info("Устанавливаю и регистрирую Cloudflare WARP...")
            if plugin.install():
                success("WARP успешно установлен!")
            else:
                error("Не удалось выполнить установку. Проверьте интернет-соединение.")
            prompt("Нажмите Enter для продолжения")
            continue

        # ── Включение / Выключение ──
        elif choice == "1" and st.installed:
            if st.enabled:
                info("Выключаю WARP...")
                if orchestrator.disable(state, "warp"):
                    success("WARP успешно выключен.")
                else:
                    error("Ошибка при выключении WARP.")
                    _show_diagnostic_info()
            else:
                info("Включаю WARP...")
                if orchestrator.enable(state, "warp"):
                    success("WARP успешно включен.")
                else:
                    error("Ошибка при включении WARP.")
                    _show_diagnostic_info()
            prompt("Нажмите Enter для продолжения")

        # ── Управление доменами ──
        elif choice == "2" and st.installed:
            _menu_manage_domains(state, ps)

        # ── Управление IP/подсетями ──
        elif choice == "3" and st.installed:
            _menu_manage_ips(state, ps)

        # ── Внешний источник ──
        elif choice == "4" and st.installed:
            _menu_external_source(state, ps, plugin)

        # ── Гео-профили (релеи) ──
        elif choice == "5" and st.installed:
            _menu_geo_profiles(state, ps)

        # ── Переустановка ──
        elif choice == "8" and st.installed:
            warn("ПЕРЕУСТАНОВКА WARP!")
            warn("Текущие ключи и сгенерированный профиль будут удалены и созданы заново.")
            if confirm("Продолжить?", default=False):
                info("Удаляю текущий профиль...")
                plugin.uninstall()
                info("Генерирую новый профиль...")
                if plugin.install():
                    success("Профиль успешно пересоздан!")
                    if st.enabled:
                        info("Применяю конфигурацию...")
                        if not orchestrator.apply_config(state):
                            error("Не удалось применить новый конфиг.")
                            _show_diagnostic_info()
                else:
                    error("Ошибка генерации нового профиля.")
            prompt("Нажмите Enter для продолжения")

        # ── Удаление ──
        elif choice == "9" and st.installed:
            warn("ПОЛНОЕ УДАЛЕНИЕ WARP!")
            warn("Будут удалены все конфигурационные файлы, wgcf и локальные правила.")
            if confirm("Вы уверены?", default=False):
                info("Удаляю...")
                if orchestrator.disable(state, "warp"):
                    plugin.uninstall()
                    success("WARP полностью удалён с сервера.")
                else:
                    error("Не удалось отключить WARP перед удалением.")
                    _show_diagnostic_info()
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление доменами ──
def _menu_manage_domains(state: AppState, ps) -> None:
    while True:
        clear()
        domains = ps.config.setdefault("domains", DEFAULT_WARP_DOMAINS.copy())
        
        lines = [
            f"  {BOLD}Список локальных доменов, направляемых в WARP:{NC}",
            "  " + "─" * 50
        ]
        if not domains:
            lines.append(f"  {DIM}Список пуст{NC}")
        else:
            for idx, domain in enumerate(domains, 1):
                lines.append(f"  {CYAN}{idx:<4}{NC} {domain}")
                
        panel("📝 ЛОКАЛЬНЫЕ ДОМЕНЫ WARP", lines)
        
        opts = [
            ("1", "➕ Добавить домен(ы)", "Добавить домены для туннелирования"),
            ("2", "🗑️  Удалить домен(ы)", "Удалить домены из списка"),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(opts, "УПРАВЛЕНИЕ ДОМЕНАМИ")
        if choice == "0":
            break
        
        elif choice == "1":
            raw = prompt("Введите домен(ы) (через пробел или запятую)").strip()
            if not raw:
                continue
            
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            added = 0
            for t in tokens:
                from hydra.plugins.warp.plugin import WarpPlugin
                if not WarpPlugin._is_valid_domain(t):
                    warn(f"Некорректный формат домена: '{t}' (пропущено)")
                    continue
                if t not in domains:
                    domains.append(t)
                    added += 1
            
            if added:
                ps.config["domains"] = domains
                save_state(state)
                success(f"Добавлено доменов: {added}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                warn("Новых доменов не добавлено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "2":
            if not domains:
                error("Список пуст.")
                prompt("Нажмите Enter")
                continue
                
            raw = prompt("Введите домен или его порядковый номер").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            removed = 0
            for t in tokens:
                if t.isdigit():
                    idx = int(t) - 1
                    if 0 <= idx < len(domains):
                        domain_to_remove = domains[idx]
                        domains.remove(domain_to_remove)
                        removed += 1
                else:
                    if t in domains:
                        domains.remove(t)
                        removed += 1
            
            if removed:
                ps.config["domains"] = domains
                save_state(state)
                success(f"Удалено доменов: {removed}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                error("Ничего не удалено. Проверьте правильность ввода.")
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление IP/подсетями ──
def _menu_manage_ips(state: AppState, ps) -> None:
    while True:
        clear()
        ips = ps.config.setdefault("ips", [])
        
        lines = [
            f"  {BOLD}Список локальных IP/подсетей, направляемых в WARP:{NC}",
            "  " + "─" * 50
        ]
        if not ips:
            lines.append(f"  {DIM}Список пуст (весь трафик по IP идет напрямую){NC}")
        else:
            for idx, ip in enumerate(ips, 1):
                lines.append(f"  {CYAN}{idx:<4}{NC} {ip}")
                
        panel("📝 ЛОКАЛЬНЫЕ IP И ПОДСЕТИ WARP", lines)
        
        opts = [
            ("1", "➕ Добавить IP/подсеть(и)", "Добавить IP или CIDR для туннелирования"),
            ("2", "🗑️  Удалить IP/подсеть(и)", "Удалить IP или CIDR из списка"),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(opts, "УПРАВЛЕНИЕ IP/ПОДСЕТЯМИ")
        if choice == "0":
            break
            
        elif choice == "1":
            raw = prompt("Введите IP/подсеть(и) (через пробел или запятую)").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            added = 0
            for t in tokens:
                from hydra.plugins.warp.plugin import WarpPlugin
                if not WarpPlugin._is_ip_or_cidr(t):
                    warn(f"Некорректный IP или CIDR: '{t}' (пропущено)")
                    continue
                if t not in ips:
                    ips.append(t)
                    added += 1
                    
            if added:
                ps.config["ips"] = ips
                save_state(state)
                success(f"Добавлено IP/подсетей: {added}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                warn("Новых записей не добавлено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "2":
            if not ips:
                error("Список пуст.")
                prompt("Нажмите Enter")
                continue
                
            raw = prompt("Введите IP/CIDR или порядковый номер").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            removed = 0
            for t in tokens:
                if t.isdigit():
                    idx = int(t) - 1
                    if 0 <= idx < len(ips):
                        ip_to_remove = ips[idx]
                        ips.remove(ip_to_remove)
                        removed += 1
                else:
                    if t in ips:
                        ips.remove(t)
                        removed += 1
                        
            if removed:
                ps.config["ips"] = ips
                save_state(state)
                success(f"Удалено записей: {removed}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                error("Ничего не удалено. Проверьте правильность ввода.")
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Настройка внешнего источника ──
def _menu_external_source(state: AppState, ps, plugin) -> None:
    from hydra.plugins.warp.plugin import EXTERNAL_LISTS
    while True:
        clear()
        enabled_lists = ps.config.setdefault("enabled_external_lists", [])
        ext_domains, ext_ips, ext_updated = _get_external_info()
        
        status_lines = []
        for key, item in EXTERNAL_LISTS.items():
            status_ico = "🟢" if key in enabled_lists else "🔴"
            status_txt = "Активен" if key in enabled_lists else "Отключен"
            color = GREEN if key in enabled_lists else RED
            
            filename = item['url'].split('/')[-1]
            short_desc = item['desc'].split(' (')[0]
            
            status_lines.append(f"  {status_ico}  {BOLD}{item['name']:<14}{NC} {DIM}({filename}){NC}")
            status_lines.append(f"     {color}{status_txt:<8}{NC}  {DIM}│{NC}  {short_desc}")
            status_lines.append("")
            
        status_lines.append("  " + "─" * 70)
        
        if enabled_lists:
            status_lines.append(f"  {BOLD}Состояние кэша правил:{NC}")
            status_lines.append(f"  • Внешних доменов в кэше:  {GREEN}{len(ext_domains)}{NC}")
            status_lines.append(f"  • Внешних IP/CIDR в кэше:  {GREEN}{len(ext_ips)}{NC}")
            if ext_updated:
                dt = ext_updated.split('.')[0].replace('T', ' ')
                status_lines.append(f"  • Последнее обновление:    {CYAN}{dt}{NC}")
            else:
                status_lines.append(f"  • Последнее обновление:    {YELLOW}требуется запуск обновления{NC}")
        else:
            status_lines.append(f"  {DIM}Нет активных внешних списков. Выберите списки ниже для включения.{NC}")
            
        panel("🔗 ВНЕШНИЕ ИСТОЧНИКИ ПРАВИЛ (itdoginfo)", status_lines)
        
        opts = []
        # Динамически выводим опции переключения списков
        for idx, (key, item) in enumerate(EXTERNAL_LISTS.items(), start=1):
            action = "Отключить" if key in enabled_lists else "Включить"
            opts.append((str(idx), f"Toggle {item['name']}", f"{action} {item['name']}"))
            
        opts.append(("4", "🔄 Обновить списки сейчас", "Скачать и применить активные списки правил"))
        opts.append(("0", "↩ Назад", ""))
        
        choice = menu(opts, "ВНЕШНИЕ ИСТОЧНИКИ")
        if choice == "0":
            break
            
        elif choice in ("1", "2", "3"):
            keys = list(EXTERNAL_LISTS.keys())
            key = keys[int(choice) - 1]
            if key in enabled_lists:
                enabled_lists.remove(key)
                action_text = "отключен"
            else:
                enabled_lists.append(key)
                action_text = "включен"
                
            ps.config["enabled_external_lists"] = enabled_lists
            save_state(state)
            success(f"Список {EXTERNAL_LISTS[key]['name']} успешно {action_text}!")
            
            # Сразу предлагаем обновить/переприменить
            if enabled_lists:
                info("Обновляю внешние правила...")
                ok, msg = plugin.update_external_rules()
                if ok:
                    success(msg)
                    if ps.enabled:
                        info("Применяю новые правила в Sing-Box...")
                        if not orchestrator.apply_config(state):
                            error("Ошибка применения нового конфига.")
                            _show_diagnostic_info()
                else:
                    error(msg)
            else:
                # Очищаем кэш и применяем
                plugin.update_external_rules()
                if ps.enabled:
                    info("Применяю изменения в Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "4":
            if not enabled_lists:
                warn("Нет активных списков для обновления.")
                prompt("Нажмите Enter для продолжения")
                continue
                
            info("Обновляю списки правил...")
            ok, msg = plugin.update_external_rules()
            if ok:
                success(msg)
                if ps.enabled:
                    info("Применяю новые правила в Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                error(msg)
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление гео-профилями ──
def _menu_geo_profiles(state: AppState, ps) -> None:
    from hydra.plugins.warp.plugin import WARP_PROFILES_DIR
    WARP_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    
    while True:
        clear()
        
        # Получаем список профилей
        profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
        routes_config = ps.config.setdefault("routes", {})

        status_lines = [
            f"  {BOLD}Каталог профилей:{NC} {WARP_PROFILES_DIR}",
            f"  Для добавления нового профиля загрузите .conf файл в этот каталог.",
            "  " + "─" * 60
        ]
        
        if not profiles:
            status_lines.append(f"  {YELLOW}Нет обнаруженных гео-профилей.{NC}")
            status_lines.append("  Система работает в стандартном режиме (один общий WARP).")
        else:
            for idx, name in enumerate(profiles, 1):
                # Читаем инфо о профиле
                routes = routes_config.setdefault(name, {"domains": [], "ips": []})
                domains_count = len(routes.get("domains", []))
                ips_count = len(routes.get("ips", []))
                
                # Проверим, есть ли AmneziaWG в этом профиле
                is_amnezia = False
                h4_warning = False
                try:
                    conf_text = (WARP_PROFILES_DIR / f"{name}.conf").read_text(encoding="utf-8", errors="replace")
                    is_amnezia = any(k in conf_text.lower() for k in ["s1", "s2", "jc", "jmin", "jmax"])
                    import re
                    h4_match = re.search(r"H4\s*=\s*(\d+)", conf_text, re.IGNORECASE)
                    if h4_match and int(h4_match.group(1)) > 255:
                        h4_warning = True
                except Exception:
                    pass
                
                type_str = f"{CYAN}AmneziaWG{NC}" if is_amnezia else f"{BLUE}WireGuard{NC}"
                warn_str = f" {RED}(⚠ H4 > 255){NC}" if h4_warning else ""
                
                status_lines.append(
                    f"  {idx}. {BOLD}{name:<15}{NC} [{type_str}]{warn_str} "
                    f"│ Маршрутов: {domains_count} доменов, {ips_count} IP"
                )
                
        panel("⚙️ ГЕО-ПРОФИЛИ WARP (РЕЛЕИ)", status_lines)
        
        options = []
        if profiles:
            options.append(("1", "📝 Настроить маршруты для профиля", "Выбрать профиль и добавить/удалить домены/IP"))
            options.append(("2", "🗑️  Удалить файл профиля", "Удалить .conf файл с диска"))
        options.append(("3", "💡 Показать инструкцию по установке", "Как получить конфиг и скопировать на сервер"))
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ГЕО-ПРОФИЛИ WARP")
        if choice == "0":
            break
            
        elif choice == "1" and profiles:
            # Выбор профиля
            opts_prof = []
            for i, name in enumerate(profiles, start=1):
                opts_prof.append((str(i), name, f"Настроить домены/IP для {name}"))
            opts_prof.append(("0", "Назад", ""))
            
            p_choice = menu(opts_prof, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ НАСТРОЙКИ")
            if p_choice == "0" or not p_choice.isdigit():
                continue
                
            idx = int(p_choice) - 1
            if 0 <= idx < len(profiles):
                _menu_manage_profile_routes(state, ps, profiles[idx])
                
        elif choice == "2" and profiles:
            opts_prof = []
            for i, name in enumerate(profiles, start=1):
                opts_prof.append((str(i), name, f"УДАЛИТЬ {name}.conf"))
            opts_prof.append(("0", "Назад", ""))
            
            p_choice = menu(opts_prof, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ УДАЛЕНИЯ")
            if p_choice == "0" or not p_choice.isdigit():
                continue
                
            idx = int(p_choice) - 1
            if 0 <= idx < len(profiles):
                name = profiles[idx]
                if confirm(f"Вы действительно хотите удалить профиль '{name}' ({name}.conf)?", default=False):
                    (WARP_PROFILES_DIR / f"{name}.conf").unlink(missing_ok=True)
                    if name in routes_config:
                        del routes_config[name]
                    save_state(state)
                    success(f"Профиль {name} успешно удален.")
                    if ps.enabled:
                        info("Обновляю конфигурацию Sing-Box...")
                        if not orchestrator.apply_config(state):
                            error("Ошибка применения нового конфига.")
                            _show_diagnostic_info()
                    prompt("Нажмите Enter для продолжения")
                    
        elif choice == "3":
            clear()
            lines = [
                f"  {BOLD}Как настроить гео-WARP релей:{NC}",
                "",
                "  1. Сгенерируйте профиль через Telegram-бота (например, @warp3_bot) или сайт.",
                "  2. Скачайте полученный .conf файл (например, 'russia.conf' или 'finland.conf').",
                "  3. Подключитесь к вашему VPS по SFTP (используя FileZilla, WinSCP или команду scp).",
                f"  4. Скопируйте файл в каталог на сервере: {GREEN}{WARP_PROFILES_DIR}{NC}",
                "     Имя файла (без .conf) будет использоваться как имя гео-профиля.",
                "  5. Вернитесь в это меню, выберите профиль и настройте для него список доменов.",
                "  6. Нажмите 'Применить/Включить' WARP, чтобы обновить конфигурацию Sing-Box.",
                "",
                "  Важно: Название файла должно содержать только английские буквы, цифры и дефис.",
                "  Пример: russia.conf, finland.conf, nl-amsterdam.conf",
            ]
            panel("ИНСТРУКЦИЯ ПО УСТАНОВКЕ", lines)
            prompt("Нажмите Enter, чтобы вернуться")


# ── Вспомогательное меню: Управление маршрутами гео-профилей ──
def _menu_manage_profile_routes(state: AppState, ps, profile_name: str) -> None:
    routes_config = ps.config.setdefault("routes", {})
    route = routes_config.setdefault(profile_name, {"domains": [], "ips": []})
    
    while True:
        clear()
        domains = route.setdefault("domains", [])
        ips = route.setdefault("ips", [])
        
        status_lines = [
            f"  Профиль:       {GREEN}{profile_name}{NC}",
            "  " + "─" * 50,
            f"  Доменов в маршруте:     {CYAN}{len(domains)}{NC}",
            f"  IP/подсетей в маршруте:  {CYAN}{len(ips)}{NC}",
            "",
            f"  Примеры доменов: {DIM}openai.com, .googlevideo.com{NC}",
            f"  Примеры IP:      {DIM}142.250.0.0/16, 8.8.8.8{NC}",
        ]
        panel(f"📝 МАРШРУТЫ ГЕО-ПРОФИЛЯ: {profile_name.upper()}", status_lines)
        
        options = [
            ("1", "➕ Добавить домен(ы)", "Добавить домены для маршрутизации через этот релей"),
            ("2", "🗑️  Удалить домен(ы)", "Показать список и удалить домены"),
            ("3", "➕ Добавить IP/подсеть(и)", "Добавить IP/CIDR для маршрутизации через этот релей"),
            ("4", "🗑️  Удалить IP/подсеть(и)", "Показать список и удалить IP/CIDR"),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(options, f"МАРШРУТЫ ДЛЯ {profile_name.upper()}")
        if choice == "0":
            break
            
        elif choice == "1":
            raw = prompt("Введите домен(ы) (через пробел или запятую)").strip()
            if not raw:
                continue
            
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            added = 0
            from hydra.plugins.warp.plugin import WarpPlugin
            for t in tokens:
                if not WarpPlugin._is_valid_domain(t):
                    warn(f"Некорректный формат домена: '{t}' (пропущено)")
                    continue
                if t not in domains:
                    domains.append(t)
                    added += 1
            
            if added:
                route["domains"] = domains
                save_state(state)
                success(f"Добавлено доменов: {added}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                warn("Новых доменов не добавлено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "2":
            if not domains:
                error("Список доменов пуст.")
                prompt("Нажмите Enter")
                continue
                
            clear()
            lines = [f"  {idx}. {d}" for idx, d in enumerate(domains, 1)]
            panel(f"СПИСОК ДОМЕНОВ ДЛЯ {profile_name.upper()}", lines)
            
            raw = prompt("Введите домен или его порядковый номер для удаления").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            removed = 0
            for t in tokens:
                if t.isdigit():
                    idx = int(t) - 1
                    if 0 <= idx < len(domains):
                        domains.remove(domains[idx])
                        removed += 1
                else:
                    if t in domains:
                        domains.remove(t)
                        removed += 1
            
            if removed:
                route["domains"] = domains
                save_state(state)
                success(f"Удалено доменов: {removed}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                error("Ничего не удалено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "3":
            raw = prompt("Введите IP/подсеть(и) (через пробел или запятую)").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            added = 0
            from hydra.plugins.warp.plugin import WarpPlugin
            for t in tokens:
                if not WarpPlugin._is_ip_or_cidr(t):
                    warn(f"Некорректный IP или CIDR: '{t}' (пропущено)")
                    continue
                if t not in ips:
                    ips.append(t)
                    added += 1
                    
            if added:
                route["ips"] = ips
                save_state(state)
                success(f"Добавлено IP/подсетей: {added}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                warn("Новых записей не добавлено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "4":
            if not ips:
                error("Список IP пуст.")
                prompt("Нажмите Enter")
                continue
                
            clear()
            lines = [f"  {idx}. {ip}" for idx, ip in enumerate(ips, 1)]
            panel(f"СПИСОК IP ДЛЯ {profile_name.upper()}", lines)
            
            raw = prompt("Введите IP/CIDR или порядковый номер для удаления").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            removed = 0
            for t in tokens:
                if t.isdigit():
                    idx = int(t) - 1
                    if 0 <= idx < len(ips):
                        ips.remove(ips[idx])
                        removed += 1
                else:
                    if t in ips:
                        ips.remove(t)
                        removed += 1
                        
            if removed:
                route["ips"] = ips
                save_state(state)
                success(f"Удалено записей: {removed}")
                if ps.enabled:
                    info("Обновляю конфигурацию Sing-Box...")
                    if not orchestrator.apply_config(state):
                        error("Ошибка применения нового конфига.")
                        _show_diagnostic_info()
            else:
                error("Ничего не удалено.")
            prompt("Нажмите Enter для продолжения")
