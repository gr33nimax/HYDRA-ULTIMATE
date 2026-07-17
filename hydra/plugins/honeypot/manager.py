"""
hydra/plugins/honeypot/manager.py — TUI-консоль управления Honeypot.
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

from hydra.core.state import AppState
from hydra.ui.tui import (
    clear, menu, prompt, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC
)

HONEYPOT_LOG = Path("/var/log/hydra-honeypot.log")

def menu_honeypot(state: AppState, plugin) -> None:
    while True:
        clear()
        
        cfg = plugin._load_state()
        port = cfg.get("port", 9999)
        wl = cfg.get("whitelist", ["127.0.0.1", "::1"])
        banned = cfg.get("banned", {})
        
        # Проверяем реальный статус сервиса
        r = subprocess.run(["systemctl", "is-active", "hydra-honeypot"], capture_output=True, text=True)
        active = r.stdout.strip() == "active"
        
        status_lines = [
            f"  Сервис:      {(GREEN+'● активен') if active else (DIM+'○ остановлен')}{NC}",
            f"  Порт:        {CYAN}{port}{NC}",
            f"  Забанено:    {(RED if banned else DIM)}{len(banned)}{NC} IP (всего)"
        ]
        
        panel("🍯 HONEYPOT-ПОРТ (ловушка сканеров)", status_lines)
        
        options = [
            ("1", f"{'⏸️  Остановить' if active else '▶️  Запустить'} Honeypot", "Переключить статус сервиса"),
            ("2", f"Изменить порт {DIM}(текущий: {port}){NC}", "Сменить прослушиваемый TCP-порт"),
            ("3", f"Управление whitelist {DIM}({len(wl)} IP){NC}", "Список доверенных IP"),
            ("4", f"Список пойманных IP {DIM}({len(banned)} шт.){NC}", "Просмотр всех забаненных адресов"),
            ("5", "🔓 Разбанить IP", "Удалить адрес из UFW и базы"),
            ("6", "📋 Последние 30 строк лога", "Просмотреть лог-файл ловушки"),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(options, "УПРАВЛЕНИЕ HONEYPOT")
        
        if choice == "0":
            break
            
        if choice == "1":
            from hydra.core.state import get_protocol, save_state
            proto = get_protocol(state, "honeypot")
            if active:
                info("Останавливаю Honeypot...")
                plugin.on_disable(state)
                if proto:
                    proto.enabled = False
                state.security.honeypot_enabled = False
                save_state(state)
                success("Honeypot остановлен.")
            else:
                info("Запускаю Honeypot...")
                if not plugin.install():
                    error("Не найдены обязательные зависимости: python3/systemd")
                    prompt("Нажмите Enter для продолжения")
                    continue
                try:
                    plugin.on_enable(state)
                except RuntimeError as exc:
                    error(str(exc))
                else:
                    if proto:
                        proto.installed = True
                        proto.enabled = True
                    state.security.honeypot_enabled = True
                    save_state(state)
                    success(f"Honeypot запущен на порту {port}.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "2":
            clear()
            raw = prompt(f"Новый порт", default=str(port)).strip()
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                new_port = int(raw)
                
                # Проверяем порты Xray / других протоколов
                from hydra.core.state import get_protocol
                conflicting = []
                for proto_name in state.protocols:
                    proto_state = get_protocol(state, proto_name)
                    if proto_state and proto_state.enabled and proto_state.port == new_port:
                        conflicting.append(proto_name)
                        
                if conflicting:
                    error(f"Порт {new_port} уже занят протоколом: {', '.join(conflicting)}!")
                    prompt("Нажмите Enter для продолжения")
                    continue
                    
                cfg["port"] = new_port
                plugin._save_state(cfg)
                
                if active:
                    info("Перезапускаю Honeypot с новым портом...")
                    plugin._remove_service()
                    if not plugin._install_service(new_port, wl):
                        cfg["port"] = port
                        plugin._save_state(cfg)
                        plugin._install_service(port, wl)
                        error("Новый порт не удалось активировать; восстановлен прежний")
                        prompt("Нажмите Enter для продолжения")
                        continue
                success(f"Порт изменен на {new_port}")
            else:
                error("Некорректный номер порта!")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "3":
            while True:
                clear()
                wl_lines = []
                for i, ip in enumerate(wl, 1):
                    wl_lines.append(f"  {CYAN}{i:>2}.{NC} {ip}")
                
                panel("Доверенные IP (Whitelist)", wl_lines)
                
                wl_opts = [
                    ("1", "➕ Добавить IP", "Внести адрес в whitelist"),
                    ("2", "➖ Удалить IP", "Исключить адрес из whitelist"),
                    ("0", "↩ Назад", "")
                ]
                wl_choice = menu(wl_opts, "WHITELIST HONEYPOT")
                
                if wl_choice == "0":
                    break
                elif wl_choice == "1":
                    new_ip = prompt("Введите IP или подсеть CIDR").strip()
                    try:
                        normalized = str(ipaddress.ip_network(new_ip, strict=False))
                    except ValueError:
                        error("Некорректный IP или CIDR.")
                        prompt("Нажмите Enter для продолжения")
                        continue
                    if normalized not in wl:
                        wl.append(normalized)
                        cfg["whitelist"] = wl
                        plugin._save_state(cfg)
                        if active:
                            plugin._write_script(port, wl)
                            subprocess.run(["systemctl", "restart", "hydra-honeypot"], capture_output=True)
                        success(f"Добавлен в whitelist: {normalized}")
                    else:
                        warn("IP пуст или уже в списке.")
                    prompt("Нажмите Enter для продолжения")
                elif wl_choice == "2":
                    if not wl:
                        warn("Список пуст.")
                        prompt("Нажмите Enter...")
                        continue
                    raw_n = prompt("Номер для удаления").strip()
                    if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl):
                        removed = wl.pop(int(raw_n) - 1)
                        cfg["whitelist"] = wl
                        plugin._save_state(cfg)
                        if active:
                            plugin._write_script(port, wl)
                            subprocess.run(["systemctl", "restart", "hydra-honeypot"], capture_output=True)
                        success(f"Удален из whitelist: {removed}")
                    else:
                        error("Неверный номер.")
                    prompt("Нажмите Enter для продолжения")
                    
        elif choice == "4":
            clear()
            banned_lines = []
            if not banned:
                banned_lines.append(f"  {DIM}Список пойманных IP пуст{NC}")
            else:
                banned_lines.append(f"  {BOLD}{'IP':<24} {'Время бана':<20} Источник{NC}")
                banned_lines.append("  " + "─" * 58)
                for ip, meta in list(banned.items())[-30:]:
                    ts = meta.get("banned_at", "?")[:16].replace("T", " ")
                    src = meta.get("source", "honeypot")
                    banned_lines.append(f"  {RED}{ip:<24}{NC} {DIM}{ts:<20}{NC} {src}")
                if len(banned) > 30:
                    banned_lines.append(f"  {DIM}... и еще {len(banned)-30} IP{NC}")
            
            panel(f"ПОЙМАННЫЕ IP ({len(banned)} шт.)", banned_lines)
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "5":
            clear()
            if not banned:
                warn("Список пойманных IP пуст.")
                prompt("Нажмите Enter для продолжения")
                continue
                
            ban_list = list(banned.keys())[-20:]
            list_lines = []
            for i, ip in enumerate(ban_list, 1):
                list_lines.append(f"  {CYAN}{i:>2}.{NC} {RED}{ip}{NC}")
                
            panel("Выберите IP для разбана", list_lines)
            raw = prompt("Номер или IP").strip()
            target = ""
            if raw.isdigit():
                idx = int(raw) - 1
                if 0 <= idx < len(ban_list):
                    target = ban_list[idx]
            elif raw in banned:
                target = raw
                
            if target:
                info(f"Разбаниваю {target}...")
                if plugin._unban_ip(target):
                    success(f"Разбанен: {target}")
                else:
                    error("Firewall не подтвердил удаление правила; запись сохранена")
            else:
                error("IP не найден.")
            prompt("Нажмите Enter для продолжения")
            
        elif choice == "6":
            clear()
            if HONEYPOT_LOG.exists():
                try:
                    lines = HONEYPOT_LOG.read_text(errors="replace").splitlines()[-30:]
                except Exception:
                    lines = []
                log_lines = []
                if not lines:
                    log_lines.append(f"  {DIM}Лог пуст{NC}")
                for line in lines:
                    col = RED if "BAN" in line else (YELLOW if "CONNECT" in line else DIM)
                    log_lines.append(f"  {col}{line[:100]}{NC}")
                panel("📋 ЛОГ HONEYPOT (последние 30 строк)", log_lines)
            else:
                warn("Лог пуст или еще не создан.")
            prompt("Нажмите Enter для продолжения")
