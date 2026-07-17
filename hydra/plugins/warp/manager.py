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
from hydra.plugins.warp.plugin import DEFAULT_WARP_DOMAINS, WARP_EXTERNAL_CACHE, WGCF_PROFILE


def _get_external_info() -> tuple[list[str], list[str], str]:
    """Возвращает (domains, ips, updated_at)."""
    if not WARP_EXTERNAL_CACHE.exists():
        return [], [], ""
    try:
        data = json.loads(WARP_EXTERNAL_CACHE.read_text(encoding="utf-8"))
        # Поддержка словаря (нового формата)
        if isinstance(data, dict) and "domains" not in data:
            domains = []
            ips = []
            for key, val in data.items():
                if key != "updated_at" and isinstance(val, dict):
                    domains.extend(val.get("domains", []))
                    ips.extend(val.get("ips", []))
            return list(set(domains)), list(set(ips)), data.get("updated_at", "")
        # Поддержка старого формата
        return data.get("domains", []), data.get("ips", []), data.get("updated_at", "")
    except Exception:
        return [], [], ""


def _get_last_install_error() -> str:
    path = Path("/var/log/hydra/install.log")
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in reversed(lines):
            line_upper = line.upper()
            if "[ERROR]" in line_upper or "CONFIG INVALID" in line_upper or "FAILED" in line_upper:
                return line
    except Exception:
        pass
    return ""


def _show_diagnostic_info():
    print(f"\n  {YELLOW}═══════════════ ДИАГНОСТИКА ОШИБКИ ═══════════════{NC}")
    
    install_err = _get_last_install_error()
    if install_err:
        warn("Последняя ошибка из /var/log/hydra/install.log:")
        print(f"  {RED}{install_err}{NC}")
    
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

    import subprocess
    r = subprocess.run(["systemctl", "status", "sing-box"], capture_output=True, text=True)
    if r.returncode != 0:
        warn("Служба sing-box неактивна или сообщает об ошибке.")
    
    r2 = subprocess.run(["journalctl", "-u", "sing-box", "-n", "10", "--no-pager"], capture_output=True, text=True)
    if r2.stdout:
        warn("Последние 10 строк логов sing-box из journalctl:")
        for line in r2.stdout.splitlines():
            print(f"  {DIM}{line}{NC}")
            
    print(f"  {YELLOW}══════════════════════════════════════════════════{NC}\n")


def menu_warp(state: AppState, plugin) -> None:
    ps = state.protocols.setdefault("warp", state.protocols.get("warp") or __import__("hydra.core.state").core.state.PluginState())
    if not ps.config:
        ps.config = {}

    from hydra.plugins.warp.plugin import WARP_PROFILES_DIR
    WARP_PROFILES_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        clear()

        # Получаем статус
        st = plugin.status()
        
        # Определяем доступные точки выхода
        destinations = ["direct"]
        custom_profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
        for p in custom_profiles:
            destinations.append(f"warp_{p}")
        if WGCF_PROFILE.exists():
            destinations.append("warp")

        # Читаем списки
        local_lists = ps.config.setdefault("local_lists", {})
        list_targets = ps.config.setdefault("list_targets", {})

        status_lines = []
        if not st.installed and not custom_profiles:
            status_lines.append(f"  Статус:      {RED}не установлен{NC} (нет WGCF профиля и гео-релеев)")
        else:
            status_lines.append(f"  Статус:      {(GREEN+'● активен') if st.running else (DIM+'○ остановлен (выключен)')}{NC}")
            status_lines.append(f"  Включён:     {GREEN if st.enabled else DIM}{'да' if st.enabled else 'нет'}{NC}")
            status_lines.append("  " + "─" * 45)
            
            status_lines.append(f"  {BOLD}Точки выхода (Egress):{NC}")
            status_lines.append(f"  • direct:         {GREEN}работает{NC}")
            if "warp" in destinations:
                status_lines.append(f"  • warp (дефолт):  {GREEN}активен{NC}")
            else:
                status_lines.append(f"  • warp (дефолт):  {DIM}не настроен{NC}")
            
            for p in custom_profiles:
                status_lines.append(f"  • warp_{p}:       {CYAN}активен (релей){NC}")

            status_lines.append("  " + "─" * 45)

            status_lines.append(f"  {BOLD}Маршруты списков правил:{NC}")
            active_routes = 0
            for list_key, target in list_targets.items():
                if not target or target == "none":
                    continue
                active_routes += 1
                
                if list_key.startswith("ext:"):
                    from hydra.plugins.warp.plugin import EXTERNAL_LISTS
                    ext_key = list_key.split(":", 1)[1]
                    list_name = EXTERNAL_LISTS.get(ext_key, {}).get("name", ext_key) + " (внешн.)"
                else:
                    list_name = list_key.split(":", 1)[1] + " (локал.)"
                
                target_color = GREEN if target != "direct" else YELLOW
                status_lines.append(f"  • {list_name:<22} → {target_color}{target}{NC}")

            if active_routes == 0:
                status_lines.append(f"  {YELLOW}Нет активных маршрутов. Настройте их ниже.{NC}")

        panel("🌐 УПРАВЛЕНИЕ WARP ROUTING & RELAYS", status_lines)

        options = []
        if not st.installed and not custom_profiles:
            options.append(("1", "🔧 Установить Cloudflare WARP (WGCF)", "Скачать и настроить локальный профиль по умолчанию"))
            options.append(("4", "⚙️ Управление профилями релеев", "Добавить сторонние профили AmneziaWG/WireGuard"))
        else:
            options.append(("1", f"{'⏸️  Выключить' if st.enabled else '▶️  Включить'} WARP", "Переключить статус службы в Sing-Box"))
            options.append(("2", "📋 Управление списками правил", "Добавление/редактирование локальных и внешних списков"))
            options.append(("3", "🔀 Настройка маршрутизации", "Связать списки правил с точками выхода (WARP/релеи)"))
            options.append(("4", "⚙️ Управление профилями релеев", "Добавить/удалить кастомные профили релеев в /etc/hydra/warp_profiles/"))
            options.append(("5", "🔄 Обновить внешние списки сейчас", "Загрузить свежие списки правил с GitHub"))
            options.append(("-", "", ""))
            if WGCF_PROFILE.exists():
                options.append(("8", "🔄 Пересоздать локальный WGCF", "Перегенерировать стандартный профиль WARP"))
                options.append(("9", "❌ Удалить локальный WGCF", "Удалить стандартный профиль WARP"))
            else:
                options.append(("8", "🔧 Установить локальный WGCF", "Скачать и сгенерировать стандартный профиль WARP"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "УПРАВЛЕНИЕ WARP")

        if choice == "0":
            break

        elif choice == "1":
            if not st.installed and not custom_profiles:
                info("Устанавливаю и регистрирую Cloudflare WARP...")
                if plugin.install():
                    success("WARP успешно установлен!")
                else:
                    error("Не удалось выполнить установку.")
                prompt("Нажмите Enter для продолжения")
            else:
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

        elif choice == "2" and (st.installed or custom_profiles):
            _menu_rules_lists(state, ps)

        elif choice == "3" and (st.installed or custom_profiles):
            _menu_routing_rules(state, ps, destinations)

        elif choice == "4":
            _menu_geo_profiles(state, ps)

        elif choice == "5" and (st.installed or custom_profiles):
            info("Обновляю внешние списки правил...")
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

        elif choice == "8":
            if WGCF_PROFILE.exists():
                warn("ПЕРЕУСТАНОВКА WGCF!")
                if confirm("Продолжить?", default=False):
                    plugin.uninstall()
                    if plugin.install():
                        success("Локальный WGCF профиль успешно пересоздан!")
                        if ps.enabled:
                            orchestrator.apply_config(state)
            else:
                info("Устанавливаю локальный WGCF...")
                if plugin.install():
                    success("Локальный WGCF профиль успешно создан!")
                    if ps.enabled:
                        orchestrator.apply_config(state)
            prompt("Нажмите Enter для продолжения")

        elif choice == "9" and WGCF_PROFILE.exists():
            warn("УДАЛЕНИЕ ЛОКАЛЬНОГО WGCF!")
            if confirm("Вы уверены?", default=False):
                plugin.uninstall()
                success("Локальный WGCF профиль успешно удален.")
                if ps.enabled:
                    orchestrator.apply_config(state)
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление списками правил ──
def _menu_rules_lists(state: AppState, ps) -> None:
    while True:
        clear()
        local_lists = ps.config.setdefault("local_lists", {})
        list_targets = ps.config.setdefault("list_targets", {})
        
        status_lines = [
            f"  {BOLD}Пользовательские локальные списки:{NC}",
        ]
        
        if not local_lists:
            status_lines.append(f"  {DIM}Нет созданных локальных списков.{NC}")
        else:
            for idx, (name, val) in enumerate(local_lists.items(), 1):
                domains_cnt = len(val.get("domains", []))
                ips_cnt = len(val.get("ips", []))
                target = list_targets.get(f"local:{name}", "none")
                status_lines.append(f"  {idx}. {BOLD}{name:<15}{NC} ({domains_cnt} доменов, {ips_cnt} IP) [→ {target}]")

        status_lines.append("")
        status_lines.append("  " + "─" * 50)
        status_lines.append(f"  {BOLD}Внешние источники правил (itdoginfo):{NC}")

        from hydra.plugins.warp.plugin import EXTERNAL_LISTS
        for key, val in EXTERNAL_LISTS.items():
            target = list_targets.get(f"ext:{key}", "none")
            status = f"{GREEN}Активен [→ {target}]{NC}" if target != "none" else f"{DIM}Отключен{NC}"
            status_lines.append(f"  • {BOLD}{val['name']:<14}{NC} — {status}")

        panel("📋 УПРАВЛЕНИЕ СПИСКАМИ ПРАВИЛ", status_lines)

        options = [
            ("1", "➕ Создать локальный список", "Создать новую группу доменов/IP"),
            ("2", "📝 Редактировать локальный список", "Добавить/удалить домены и IP в локальном списке"),
            ("3", "🗑️  Удалить локальный список", "Удалить пользовательскую группу"),
            ("4", "🔗 Настройка внешних источников", "Включить/отключить списки РФ-сервисов, GEO-block и др."),
            ("0", "↩ Назад", "")
        ]

        choice = menu(options, "СПИСКИ ПРАВИЛ")
        if choice == "0":
            break

        elif choice == "1":
            name = prompt("Введите имя нового списка (латиница, цифры, дефис)").strip().lower()
            if not name or not name.isalnum():
                error("Некорректное имя списка. Разрешены только буквы и цифры.")
                prompt("Нажмите Enter")
                continue
            if name in local_lists:
                error("Список с таким именем уже существует.")
                prompt("Нажмите Enter")
                continue
            
            local_lists[name] = {"domains": [], "ips": []}
            list_targets[f"local:{name}"] = "none"
            save_state(state)
            success(f"Локальный список '{name}' успешно создан!")
            prompt("Нажмите Enter")

        elif choice == "2":
            if not local_lists:
                error("Нет доступных списков.")
                prompt("Нажмите Enter")
                continue
            
            opts_l = []
            for i, name in enumerate(local_lists.keys(), 1):
                opts_l.append((str(i), name, f"Редактировать список {name}"))
            opts_l.append(("0", "Назад", ""))

            l_choice = menu(opts_l, "ВЫБЕРИТЕ СПИСОК")
            if l_choice == "0" or not l_choice.isdigit():
                continue
            
            idx = int(l_choice) - 1
            keys = list(local_lists.keys())
            if 0 <= idx < len(keys):
                _menu_manage_local_list_items(state, ps, keys[idx])

        elif choice == "3":
            if not local_lists:
                error("Нет доступных списков.")
                prompt("Нажмите Enter")
                continue
            
            opts_l = []
            for i, name in enumerate(local_lists.keys(), 1):
                opts_l.append((str(i), name, f"УДАЛИТЬ список {name}"))
            opts_l.append(("0", "Назад", ""))

            l_choice = menu(opts_l, "ВЫБЕРИТЕ СПИСОК ДЛЯ УДАЛЕНИЯ")
            if l_choice == "0" or not l_choice.isdigit():
                continue
            
            idx = int(l_choice) - 1
            keys = list(local_lists.keys())
            if 0 <= idx < len(keys):
                name = keys[idx]
                if name == "default":
                    error("Список 'default' является системным и его нельзя удалить.")
                    prompt("Нажмите Enter")
                    continue
                if confirm(f"Вы уверены, что хотите удалить список '{name}'?", default=False):
                    del local_lists[name]
                    list_targets.pop(f"local:{name}", None)
                    save_state(state)
                    success(f"Список '{name}' успешно удален.")
                    if ps.enabled:
                        orchestrator.apply_config(state)
                prompt("Нажмите Enter")

        elif choice == "4":
            _menu_external_sources_toggle(state, ps)


# ── Вспомогательное меню: Редактирование локального списка ──
def _menu_manage_local_list_items(state: AppState, ps, list_name: str) -> None:
    local_lists = ps.config.setdefault("local_lists", {})
    route = local_lists.setdefault(list_name, {"domains": [], "ips": []})
    
    while True:
        clear()
        domains = route.setdefault("domains", [])
        ips = route.setdefault("ips", [])
        
        status_lines = [
            f"  Локальный список: {GREEN}{list_name}{NC}",
            "  " + "─" * 50,
            f"  Доменов:     {CYAN}{len(domains)}{NC}",
            f"  IP/подсетей:  {CYAN}{len(ips)}{NC}",
        ]
        panel(f"📝 РЕДАКТИРОВАНИЕ СПИСКА: {list_name.upper()}", status_lines)
        
        options = [
            ("1", "➕ Добавить домен(ы)", "Добавить домены в эту группу"),
            ("2", "🗑️  Удалить домен(ы)", "Показать список и удалить домены"),
            ("3", "➕ Добавить IP/подсеть(и)", "Добавить IP или CIDR подсети"),
            ("4", "🗑️  Удалить IP/подсеть(и)", "Показать список и удалить IP/CIDR"),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(options, f"СПИСОК {list_name.upper()}")
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
                    orchestrator.apply_config(state)
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
            panel(f"СПИСОК ДОМЕНОВ ({list_name})", lines)
            
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
                    orchestrator.apply_config(state)
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
                    orchestrator.apply_config(state)
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
            panel(f"СПИСОК IP/ПОДСЕТЕЙ ({list_name})", lines)
            
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
                    orchestrator.apply_config(state)
            else:
                error("Ничего не удалено.")
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Включение/выключение внешних списков ──
def _menu_external_sources_toggle(state: AppState, ps) -> None:
    from hydra.plugins.warp.plugin import EXTERNAL_LISTS
    while True:
        clear()
        list_targets = ps.config.setdefault("list_targets", {})
        
        status_lines = []
        for key, item in EXTERNAL_LISTS.items():
            target = list_targets.get(f"ext:{key}", "none")
            status_ico = "🟢" if target != "none" else "🔴"
            status_txt = f"Активен (→ {target})" if target != "none" else "Отключен"
            color = GREEN if target != "none" else RED
            
            filename = item['url'].split('/')[-1]
            short_desc = item['desc'].split(' (')[0]
            
            status_lines.append(f"  {status_ico}  {BOLD}{item['name']:<14}{NC} {DIM}({filename}){NC}")
            status_lines.append(f"     {color}{status_txt:<8}{NC}  {DIM}│{NC}  {short_desc}")
            status_lines.append("")
            
        panel("🔗 ВНЕШНИЕ ИСТОЧНИКИ ПРАВИЛ (itdoginfo)", status_lines)
        
        opts = []
        for idx, (key, item) in enumerate(EXTERNAL_LISTS.items(), start=1):
            target = list_targets.get(f"ext:{key}", "none")
            action = "Отключить" if target != "none" else "Включить"
            opts.append((str(idx), f"Toggle {item['name']}", f"{action} {item['name']}"))
            
        opts.append(("0", "↩ Назад", ""))
        
        choice = menu(opts, "ВНЕШНИЕ ИСТОЧНИКИ")
        if choice == "0":
            break
            
        elif choice in ("1", "2", "3"):
            keys = list(EXTERNAL_LISTS.keys())
            key = keys[int(choice) - 1]
            target = list_targets.get(f"ext:{key}", "none")
            
            if target != "none":
                list_targets[f"ext:{key}"] = "none"
                save_state(state)
                success(f"Список {EXTERNAL_LISTS[key]['name']} успешно отключен.")
                if ps.enabled:
                    orchestrator.apply_config(state)
            else:
                success(f"Включаем список {EXTERNAL_LISTS[key]['name']}.")
                from hydra.plugins.warp.plugin import WARP_PROFILES_DIR
                destinations = ["direct"]
                custom_profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
                for p in custom_profiles:
                    destinations.append(f"warp_{p}")
                if WGCF_PROFILE.exists():
                    destinations.append("warp")
                
                opts_dest = []
                for i, d in enumerate(destinations, start=1):
                    opts_dest.append((str(i), d, f"Направить трафик на {d}"))
                
                d_choice = menu(opts_dest, f"ВЫБЕРИТЕ НАПРАВЛЕНИЕ ДЛЯ {EXTERNAL_LISTS[key]['name'].upper()}")
                if d_choice.isdigit():
                    d_idx = int(d_choice) - 1
                    if 0 <= d_idx < len(destinations):
                        chosen_dest = destinations[d_idx]
                        list_targets[f"ext:{key}"] = chosen_dest
                        save_state(state)
                        success(f"Список {EXTERNAL_LISTS[key]['name']} направлен на {chosen_dest}!")
                        
                        info("Скачиваю список правил...")
                        plugin = __import__("hydra.plugins.warp.plugin").plugins.warp.plugin.WarpPlugin()
                        ok, msg = plugin.update_external_rules()
                        if ok:
                            success(msg)
                        else:
                            warn(msg)
                            
                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                            orchestrator.apply_config(state)
                            
            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Настройка маршрутизации списков ──
def _menu_routing_rules(state: AppState, ps, destinations: list[str]) -> None:
    while True:
        clear()
        list_targets = ps.config.setdefault("list_targets", {})
        local_lists = ps.config.setdefault("local_lists", {})
        
        status_lines = [
            f"  {BOLD}Текущее сопоставление списков и точек выхода:{NC}",
            "  " + "─" * 60
        ]
        
        active_rules = []
        
        # 1. Локальные списки
        for name in local_lists.keys():
            key = f"local:{name}"
            target = list_targets.get(key, "none")
            active_rules.append((key, name + " (локал.)", target))
            
        # 2. Внешние списки
        from hydra.plugins.warp.plugin import EXTERNAL_LISTS
        for name, item in EXTERNAL_LISTS.items():
            key = f"ext:{name}"
            target = list_targets.get(key, "none")
            active_rules.append((key, item["name"] + " (внешн.)", target))
            
        for idx, (key, display_name, target) in enumerate(active_rules, 1):
            target_color = GREEN if target != "none" and target != "direct" else (YELLOW if target == "direct" else DIM)
            status_lines.append(f"  {idx:<3} {display_name:<25} → {target_color}{target}{NC}")
            
        panel("🔀 МАРШРУТИЗАЦИЯ СПИСКОВ ПРАВИЛ", status_lines)
        
        opts = []
        for idx, (key, display_name, target) in enumerate(active_rules, 1):
            opts.append((str(idx), display_name, f"Изменить направление (сейчас: {target})"))
        opts.append(("0", "↩ Назад", ""))
        
        choice = menu(opts, "ВЫБЕРИТЕ МАРШРУТ ДЛЯ ИЗМЕНЕНИЯ")
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(active_rules):
                key, display_name, current_target = active_rules[idx]
                
                opts_dest = []
                for i, d in enumerate(destinations, start=1):
                    opts_dest.append((str(i), d, f"Направить на {d}"))
                opts_dest.append((str(len(destinations) + 1), "none (отключить)", "Отключить маршрутизацию этого списка"))
                opts_dest.append(("0", "Отмена", ""))
                
                d_choice = menu(opts_dest, f"НАПРАВЛЕНИЕ ДЛЯ {display_name.upper()}")
                if d_choice == "0":
                    continue
                
                if d_choice.isdigit():
                    d_idx = int(d_choice) - 1
                    if 0 <= d_idx < len(destinations):
                        chosen_dest = destinations[d_idx]
                        list_targets[key] = chosen_dest
                        save_state(state)
                        success(f"Маршрут для {display_name} изменен на {chosen_dest}!")
                        
                        if key.startswith("ext:") and chosen_dest != "none":
                            info("Скачиваю список правил...")
                            plugin = __import__("hydra.plugins.warp.plugin").plugins.warp.plugin.WarpPlugin()
                            ok, msg = plugin.update_external_rules()
                            if ok:
                                success(msg)
                            else:
                                warn(msg)
                                
                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                            orchestrator.apply_config(state)
                    elif d_idx == len(destinations):
                        list_targets[key] = "none"
                        save_state(state)
                        success(f"Маршрут для {display_name} отключен.")
                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                            orchestrator.apply_config(state)
                            
                prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление профилями релеев ──
def _menu_geo_profiles(state: AppState, ps) -> None:
    from hydra.plugins.warp.plugin import WARP_PROFILES_DIR
    WARP_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    
    while True:
        clear()
        
        profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
        list_targets = ps.config.setdefault("list_targets", {})

        status_lines = [
            f"  {BOLD}Каталог профилей:{NC} {WARP_PROFILES_DIR}",
            f"  Для добавления нового релея загрузите .conf файл в этот каталог.",
            "  " + "─" * 60
        ]
        
        if not profiles:
            status_lines.append(f"  {YELLOW}Нет обнаруженных профилей релеев.{NC}")
            status_lines.append("  Доступен только стандартный дефолтный WARP.")
        else:
            for idx, name in enumerate(profiles, 1):
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
                
                mapped_lists = []
                for k, target in list_targets.items():
                    if target == f"warp_{name}":
                        list_name = k.split(":", 1)[1]
                        mapped_lists.append(list_name)
                
                routes_str = f"Направлены списки: {', '.join(mapped_lists)}" if mapped_lists else "Нет привязанных списков"
                
                status_lines.append(
                    f"  {idx}. {BOLD}warp_{name:<12}{NC} [{type_str}]{warn_str} "
                    f"│ {DIM}{routes_str}{NC}"
                )
                
        panel("⚙️ УПРАВЛЕНИЕ ПРОФИЛЯМИ РЕЛЕЕВ", status_lines)
        
        options = []
        if profiles:
            options.append(("1", "🗑️  Удалить файл профиля релея", "Удалить .conf файл с диска"))
        options.append(("2", "💡 Показать инструкцию по установке", "Как получить конфиг и скопировать на сервер"))
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ПРОФИЛИ РЕЛЕЕВ")
        if choice == "0":
            break
            
        elif choice == "1" and profiles:
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
                if confirm(f"Вы действительно хотите удалить релей '{name}' ({name}.conf)?", default=False):
                    (WARP_PROFILES_DIR / f"{name}.conf").unlink(missing_ok=True)
                    keys_to_clean = [k for k, target in list_targets.items() if target == f"warp_{name}"]
                    for k in keys_to_clean:
                        list_targets[k] = "none"
                    save_state(state)
                    success(f"Релей warp_{name} успешно удален.")
                    if ps.enabled:
                        info("Обновляю конфигурацию Sing-Box...")
                        if not orchestrator.apply_config(state):
                            error("Ошибка применения нового конфига.")
                            _show_diagnostic_info()
                prompt("Нажмите Enter для продолжения")
                    
        elif choice == "2":
            clear()
            lines = [
                f"  {BOLD}Как настроить гео-WARP релей:{NC}",
                "",
                "  1. Сгенерируйте профиль через Telegram-бота",
                f"     {GREEN}@warp_generator_bot{NC} или сайт.",
                "  2. Скачайте полученный .conf файл",
                "     (например, 'russia.conf' или 'finland.conf').",
                "  3. Подключитесь к VPS по SFTP (FileZilla, WinSCP и др.).",
                f"  4. Скопируйте файл в каталог на сервере:",
                f"     {GREEN}{WARP_PROFILES_DIR}{NC}",
                "     Имя файла (без .conf) будет именем релея.",
                "  5. Свяжите нужные списки правил с этим релеем в меню",
                "     'Настройка маршрутизации'.",
                "  6. Включите WARP для применения конфигурации.",
                "",
                f"  {BOLD}Важно:{NC} Имя файла должно содержать только",
                "  английские буквы, цифры и дефис.",
                "  Пример: russia.conf, finland.conf, nl-amsterdam.conf",
            ]
            panel("ИНСТРУКЦИЯ ПО УСТАНОВКЕ", lines)
            prompt("Нажмите Enter, чтобы вернуться")
