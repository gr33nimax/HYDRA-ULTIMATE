"""Local rule-list interactions for the WARP manager facade."""
from __future__ import annotations

import re

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    clear,
    confirm,
    error,
    menu,
    panel,
    prompt,
    success,
    warn,
)

def _menu_rules_lists(
    state: AppState,
    ps,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        local_lists = ps.config.setdefault("local_lists", {})
        list_targets = ps.config.setdefault("list_targets", {})
        external_sources = facade._external_sources(app)
        
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

        for key, val in external_sources.items():
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
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
                error("Некорректное имя списка. Разрешены латинские буквы, цифры и дефис.")
                prompt("Нажмите Enter")
                continue
            if name in local_lists:
                error("Список с таким именем уже существует.")
                prompt("Нажмите Enter")
                continue
            
            local_lists[name] = {"domains": [], "ips": []}
            list_targets[f"local:{name}"] = "none"
            app.admin.save_state(state)
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
                _menu_manage_local_list_items(state, ps, keys[idx], app)

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
                    app.admin.save_state(state)
                    success(f"Список '{name}' успешно удален.")
                    if ps.enabled:
                        app.apply(state)
                prompt("Нажмите Enter")

        elif choice == "4":
            facade._menu_external_sources_toggle(state, ps, app)


# ── Вспомогательное меню: Редактирование локального списка ──
def _menu_manage_local_list_items(
    state: AppState,
    ps,
    list_name: str,
    app: ApplicationService,
) -> None:
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
            for t in tokens:
                if not facade._valid_domain(t):
                    warn(f"Некорректный формат домена: '{t}' (пропущено)")
                    continue
                if t not in domains:
                    domains.append(t)
                    added += 1
            
            if added:
                route["domains"] = domains
                app.admin.save_state(state)
                success(f"Добавлено доменов: {added}")
                if ps.enabled:
                    app.apply(state)
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
                app.admin.save_state(state)
                success(f"Удалено доменов: {removed}")
                if ps.enabled:
                    app.apply(state)
            else:
                error("Ничего не удалено.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "3":
            raw = prompt("Введите IP/подсеть(и) (через пробел или запятую)").strip()
            if not raw:
                continue
                
            tokens = [t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()]
            added = 0
            for t in tokens:
                if not facade._valid_ip_or_cidr(t):
                    warn(f"Некорректный IP или CIDR: '{t}' (пропущено)")
                    continue
                if t not in ips:
                    ips.append(t)
                    added += 1
                    
            if added:
                route["ips"] = ips
                app.admin.save_state(state)
                success(f"Добавлено IP/подсетей: {added}")
                if ps.enabled:
                    app.apply(state)
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
                app.admin.save_state(state)
                success(f"Удалено записей: {removed}")
                if ps.enabled:
                    app.apply(state)
            else:
                error("Ничего не удалено.")
            prompt("Нажмите Enter для продолжения")
                            
