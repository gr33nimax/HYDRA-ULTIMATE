"""
hydra/plugins/ipban/manager.py — TUI-консоль управления IP-банами.
"""
from __future__ import annotations

import time
import subprocess
from hydra.core.state import AppState
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    GREEN, CYAN, BOLD, DIM, NC
)

def menu_ipban(state: AppState, plugin) -> None:
    while True:
        clear()
        
        installed = plugin._installed()
        st_data = plugin._load_state()
        entries = st_data.get("entries", [])
        
        if installed:
            cnt_v4, cnt_v6 = plugin._ipset_count()
            # Проверяем статус правил iptables
            chk4 = subprocess.run(
                ["iptables", "-C", "INPUT", "-m", "set", "--match-set", "hydra_manual_ban", "src",
                 "-m", "comment", "--comment", "hydra-ipban", "-j", "DROP"],
                capture_output=True
            ).returncode == 0
            chk6 = subprocess.run(
                ["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", "hydra_manual_ban6", "src",
                 "-m", "comment", "--comment", "hydra-ipban", "-j", "DROP"],
                capture_output=True
            ).returncode == 0
            rules_ok = chk4 and chk6
        else:
            cnt_v4 = cnt_v6 = 0
            rules_ok = False

        status_lines = [
            f"  Статус iptables:    {f'{GREEN}активны{NC}' if rules_ok else f'{DIM}не установлены{NC}'}",
            f"  Записей в базе:     {f'{GREEN}{len(entries)}{NC}' if entries else f'{DIM}нет{NC}'}",
            f"  Активных CIDR:      {f'{GREEN}{cnt_v4} IPv4 / {cnt_v6} IPv6{NC}' if installed else f'{DIM}ipset не создан{NC}'}"
        ]
        
        panel("🚫 IP-БАН (iptables / ipset)", status_lines)
        
        options = []
        if not installed:
            options.append(("1", "🔧 Установить ipset и правила", "Необходим пакет ipset и iptables правила"))
        else:
            options.append(("1", "➕ Добавить бан", "IP / подсеть / диапазон / ASN (RIPE Stat)"))
            options.append(("2", "➖ Снять бан", "Выбрать и разбанить запись"))
            options.append(("3", "📋 Список активных банов", "Просмотр всех блокировок"))
            options.append(("4", "🔄 Восстановить из базы", "Пересоздать правила и восстановить баны"))
            options.append(("-", "", ""))
            options.append(("X", "🗑️ Снять ВСЕ баны", "Очистить базу, сбросить сеты и правила"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "УПРАВЛЕНИЕ IP-БАНАМИ")
        
        if choice == "0":
            break
            
        if not installed:
            if choice == "1":
                info("Установка ipset и настройка правил...")
                if plugin.install():
                    from hydra.core.state import get_protocol, save_state
                    proto = get_protocol(state, "ipban")
                    proto.installed = True
                    proto.enabled = True
                    state.security.ipban_enabled = True
                    save_state(state)
                    success("Успешно установлено!")
                else:
                    error("Не удалось настроить ipset. Подробнее в логе: /var/log/hydra/install.log")
                prompt("Нажмите Enter для продолжения")
            continue
            
        if choice == "1":
            clear()
            add_lines = [
                "  Форматы ввода (можно несколько через пробел или запятую):",
                "",
                f"    {CYAN}1.2.3.4{NC}              — одиночный IP",
                f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)",
                f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4",
                f"    {CYAN}AS12345{NC}              — автономная система (ASN)",
                f"    {CYAN}2001:db8::/32{NC}         — IPv6 подсеть",
                "",
                f"  {DIM}Пример: 1.2.3.4, 10.0.0.0/8, AS1234{NC}"
            ]
            panel("➕ ДОБАВИТЬ БАН", add_lines)
            
            raw_inp = prompt("Ввод").strip()
            if not raw_inp:
                continue
                
            comment_inp = prompt("Комментарий (Enter — пропустить)").strip()
            
            tokens = [t.strip() for t in raw_inp.replace(",", " ").split() if t.strip()]
            print()
            info("Применяю блокировку...")
            for token in tokens:
                try:
                    display, kind, cidrs = plugin._resolve_to_cidrs(token)
                    info(f"Разрешено в {len(cidrs)} CIDR...")
                except Exception as exc:
                    error(f"Не удалось разобрать '{token}': {exc}")
                    continue
                
                if plugin.ban_ip(token, comment=comment_inp):
                    success(f"Заблокировано: {display} ({kind}) — {len(cidrs)} CIDR")
                else:
                    error(f"Не удалось заблокировать: {token}")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "2":
            clear()
            if not entries:
                warn("Список блокировок пуст.")
                prompt("Нажмите Enter для продолжения")
                continue
                
            list_lines = []
            for idx, e in enumerate(entries, 1):
                kind_icon = {
                    "ip":    "🔹", "cidr": "🔸",
                    "range": "🔷", "asn":  "🏢",
                }.get(e.get("kind", ""), "•")
                n_cidr = len(e.get("cidrs", []))
                added  = e.get("added_at", "")[:10]
                cmt    = f" | {DIM}{e['comment']}{NC}" if e.get("comment") else ""
                list_lines.append(
                    f"  {CYAN}{idx:>2}.{NC} {kind_icon} {BOLD}{e['display']}{NC} [{n_cidr} CIDR, {added}]{cmt}"
                )
            
            panel("СНЯТЬ БАН — выберите запись", list_lines)
            
            sel = prompt("Номер или имя для разбана").strip()
            if not sel:
                continue
                
            target = None
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(entries):
                    target = entries[idx]["display"]
            else:
                for e in entries:
                    if sel.upper() == e["display"].upper():
                        target = e["display"]
                        break
                        
            if not target:
                error(f"Запись '{sel}' не найдена.")
                time.sleep(1.5)
                continue
                
            info(f"Снимаю бан с {target}...")
            if plugin.unban_ip(target):
                success(f"Разбанено: {target}")
            else:
                error(f"Не удалось разбанить {target}")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "3":
            clear()
            if not entries:
                list_lines = [f"  {DIM}Список блокировок пуст{NC}"]
            else:
                list_lines = [
                    f"  {BOLD}{'#':>3}  {'Тип':<6}  {'Запись':<28}  {'CIDR':>5}  {'Добавлен':<10}  Комментарий{NC}",
                    "  " + "─" * 68
                ]
                kind_labels = {"ip": "IP", "cidr": "CIDR", "range": "Range", "asn": "ASN"}
                for idx, e in enumerate(entries, 1):
                    kind = kind_labels.get(e.get("kind", ""), "?")
                    n_cidr = len(e.get("cidrs", []))
                    added = e.get("added_at", "")[:10]
                    cmt = e.get("comment", "")[:20]
                    disp = e.get("display", "")[:28]
                    list_lines.append(
                        f"  {CYAN}{idx:>3}.{NC}  {kind:<6}  {BOLD}{disp:<28}{NC}  {n_cidr:>5}  {DIM}{added:<10}{NC}  {DIM}{cmt}{NC}"
                    )
            
            panel("📋 АКТИВНЫЕ IP-БАНЫ", list_lines)
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "4":
            info("Восстановление правил и сетов из базы...")
            if plugin.apply(state):
                success("Готово!")
            else:
                error("Ошибка при восстановлении правил.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "X" or choice == "x":
            warn("СБРОС ВСЕХ БАНОВ!")
            warn("Будут удалены все правила iptables, ipset-сеты и очищена база данных.")
            if confirm("Вы уверены?", default=False):
                info("Очищаю...")
                if plugin._remove_iptables_rules():
                    subprocess.run(["ipset", "flush", "hydra_manual_ban"], capture_output=True)
                    subprocess.run(["ipset", "flush", "hydra_manual_ban6"], capture_output=True)
                    plugin._save_state({"entries": []})
                    if plugin._ensure_iptables_rules():
                        success("Все блокировки успешно сброшены!")
                    else:
                        error("Баны сняты, но защитные правила не удалось восстановить")
                else:
                    error("Не удалось удалить все правила firewall; база оставлена без изменений")
            else:
                info("Отменено.")
            prompt("Нажмите Enter для продолжения")
