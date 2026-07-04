"""hydra/plugins/wdtt/manager.py — TUI-консоль управления qWDTT."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from hydra.core.state import AppState, save_state, get_protocol
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error, kv, _ok,
    RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA, BOLD, DIM, WHITE, NC, box, title
)
import hydra.core.orchestrator as orchestrator
from hydra.plugins.wdtt.plugin import (
    BIN_PATH, CONFIG_DIR, CONFIG_FILE, PASSWORDS_FILE, SERVICE_FILE, SERVICE_NAME,
    DEFAULT_DTLS_PORT, DEFAULT_WG_PORT, DEFAULT_WG_SUBNET, LOCAL_TUN_PORT,
    SYSTEM_PASSWORD
)

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ══════════════════════════════════════════════════════════════════════════════

def _load_passwords() -> dict:
    if not PASSWORDS_FILE.exists():
        return {"main_password": "", "admin_id": "", "bot_token": "", "passwords": {}, "devices": {}}
    try:
        return json.loads(PASSWORDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _save_passwords(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PASSWORDS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    PASSWORDS_FILE.chmod(0o600)

def _hot_reload() -> bool:
    r = subprocess.run(["pidof", "wdtt-server"], capture_output=True, text=True)
    pid = r.stdout.strip()
    if not pid:
        return False
    subprocess.run(["kill", "-HUP", pid])
    return True

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    return "ВАШ_IP"

def _save_link_to_file(link: str, filename: str) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        path = CONFIG_DIR / filename
        path.write_text(link + "\n", encoding="utf-8")
        path.chmod(0o600)
        print(f"\n  {DIM}📄 Ссылка сохранена в файл: {NC}{CYAN}{path}{NC}")
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ WDTT
# ══════════════════════════════════════════════════════════════════════════════

def menu_wdtt(state: AppState, plugin):
    # Синхронизируем файлы на диске с AppState
    plugin.sync_fs_to_state(state)
    
    while True:
        clear()
        ps = get_protocol(state, "wdtt")
        
        # Определение статуса
        installed = plugin._installed()
        r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
        running = r.stdout.strip() == "active"
        
        svc_str = (
            f"{GREEN}● запущен{NC}" if running else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )
        
        lines = [
            f"  Статус:      {svc_str}",
            f"  Установлен:  {_ok(installed)}",
            f"  Включён:     {_ok(ps.enabled)}",
        ]
        
        if installed:
            dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
            wg_port = ps.config.get("wg_port", DEFAULT_WG_PORT)
            lines.append(f"  DTLS порт:   {dtls_port}")
            lines.append(f"  WG порт:     {wg_port}")
            
            try:
                if PASSWORDS_FILE.exists():
                    pw_data = json.loads(PASSWORDS_FILE.read_text(encoding="utf-8"))
                    pw_count = len(pw_data.get("passwords", {}))
                    dev_count = len(pw_data.get("devices", {}))
                    lines.append(f"  Паролей:     {pw_count}")
                    lines.append(f"  Устройств:   {dev_count}")
                    
                    tg = "✓ настроен" if pw_data.get("bot_token") else "не настроен"
                    tg_col = GREEN if pw_data.get("bot_token") else DIM
                    lines.append(f"  Telegram:    {tg_col}{tg}{NC}")
            except Exception:
                pass
                
        panel("🛡️ QWDTT (WireGuard over TURN)", lines)
        
        options = []
        if not installed:
            options.append(("1", "🚀 Установить qWDTT", "Сборка wdtt-server, настройка службы и NAT"))
        else:
            options.append(("1", "🚀 Переустановить", "Пересобрать и переустановить службу"))
            options.append(("2", "🔑 Управление паролями", "Просмотр, добавление и удаление паролей"))
            options.append(("3", "🔗 Показать ссылку (главный пароль)", "qwdtt:// ссылка администратора"))
            options.append(("4", "🔄 Перезапустить сервис", "Выполнить systemctl restart wdtt"))
            options.append(("5", "📊 Статус / логи", "Просмотр логов systemd и journalctl"))
            options.append(("8", "❌ Удалить qWDTT", "Полное удаление бинарников, конфигов и правил"))
            
        options.append(("G", "📖 Гайд", "Руководство по установке, VK-хешам и боту"))
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "QWDTT CONTROL")
        
        if choice == "0":
            break
        elif choice == "1":
            _run_install(state, plugin)
        elif choice == "2" and installed:
            _passwords_menu(state)
        elif choice == "3" and installed:
            _show_main_link(state)
        elif choice == "4" and installed:
            _restart_service()
        elif choice == "5" and installed:
            _show_status_logs()
        elif choice == "8" and installed:
            _uninstall_wdtt(state, plugin)
        elif choice.upper() == "G":
            _show_guide()

# ══════════════════════════════════════════════════════════════════════════════
#  МАСТЕР УСТАНОВКИ
# ══════════════════════════════════════════════════════════════════════════════

def _run_install(state: AppState, plugin):
    clear()
    title("Установка / Настройка qWDTT")
    
    ps = get_protocol(state, "wdtt")
    preserve = True
    
    if plugin._installed():
        warn("qWDTT уже установлен.")
        choice = menu([
            ("1", "Переустановить с сохранением паролей и конфига", ""),
            ("2", "Установить полностью заново (сбросить пароли)", ""),
            ("0", "Отмена", "")
        ], "ПЕРЕУСТАНОВКА")
        if choice == "0" or not choice:
            return
        if choice == "2":
            preserve = False
            
    old_pass = ""
    old_dtls = DEFAULT_DTLS_PORT
    old_wg = DEFAULT_WG_PORT
    old_admin = ""
    old_bot = ""
    
    if preserve:
        if PASSWORDS_FILE.exists():
            try:
                pw_data = json.loads(PASSWORDS_FILE.read_text(encoding="utf-8"))
                old_pass = pw_data.get("main_password", "")
                old_admin = pw_data.get("admin_id", "")
                old_bot = pw_data.get("bot_token", "")
            except Exception:
                pass
        if CONFIG_FILE.exists():
            try:
                cfg_data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                old_dtls = cfg_data.get("dtls_port", DEFAULT_DTLS_PORT)
                old_wg = cfg_data.get("wg_port", DEFAULT_WG_PORT)
            except Exception:
                pass
                
    print(f"\n  {CYAN}--- Настройка портов и паролей ---{NC}\n")
    
    main_pass = prompt("Главный пароль (оставьте пустым для автогенерации)", default=old_pass)
    if not main_pass:
        main_pass = secrets.token_hex(8) if not old_pass else old_pass
        
    dtls_str = prompt("UDP порт DTLS (входящий от TURN-сервера)", default=str(old_dtls))
    dtls_port = int(dtls_str) if dtls_str.isdigit() else old_dtls
    
    wg_str = prompt("UDP порт WireGuard (внутренний)", default=str(old_wg))
    wg_port = int(wg_str) if wg_str.isdigit() else old_wg
    
    if dtls_port == wg_port:
        error("Порты DTLS и WireGuard не должны совпадать!")
        prompt("Нажмите Enter...")
        return
        
    admin_id = prompt("Telegram Admin ID (для управления паролями, пропустить)", default=str(old_admin) if old_admin else "")
    bot_token = ""
    if admin_id:
        bot_token = prompt("Telegram Bot Token (для управления паролями, пропустить)", default=old_bot)
        
    ps.config["main_password"] = main_pass
    ps.config["dtls_port"] = dtls_port
    ps.config["wg_port"] = wg_port
    ps.config["admin_id"] = admin_id
    ps.config["bot_token"] = bot_token
    save_state(state)
    
    info("Сборка wdtt-server из исходников (это может занять 1-2 минуты)...")
    
    ok = orchestrator.install_plugin(state, "wdtt")
    if ok:
        orchestrator.enable(state, "wdtt")
        success("Установка и запуск qWDTT завершены успешно!")
        
        server_ip = state.network.server_ip or _get_server_ip()
        qwdtt_link = (
            f"qwdtt://config?name=qWDTT-{server_ip}"
            f"&peer={server_ip}:{dtls_port}"
            f"&hashes=ВК_ХЕШ_ЗВОНКА"
            f"&workers=16&port={LOCAL_TUN_PORT}"
            f"&pass={main_pass}"
        )
        print()
        box(f" Ссылка qwdtt:// для импорта в Android-клиент:\n\n{YELLOW}{qwdtt_link}{NC}\n\n"
            f" Замените ВК_ХЕШ_ЗВОНКА на хеш из ссылки vk.com/call/join/ХЕШ", 
            "БЫСТРАЯ ССЫЛКА")
        
        _save_link_to_file(qwdtt_link, "qwdtt_link.txt")
    else:
        error("Не удалось скомпилировать или запустить wdtt-server.")
        
    prompt("Нажмите Enter...")

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ВРЕМЕННЫМИ ПАРОЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════

def _passwords_menu(state: AppState):
    while True:
        clear()
        data = _load_passwords()
        passwords = data.get("passwords", {})
        server_ip = state.network.server_ip or _get_server_ip()
        ps = get_protocol(state, "wdtt")
        dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
        
        lines = [
            f"  Главный пароль:    {data.get('main_password', '—')}",
            f"  Временных паролей: {len(passwords)} / 10",
            "───────────────────────────────────────────────"
        ]
        
        active_list = []
        for pw, entry in passwords.items():
            if not entry:
                continue
            expires = entry.get("expires_at", 0)
            expired = expires > 0 and time.time() > expires
            active_list.append((pw, entry, expired))
            
        if active_list:
            lines.append(f"  {BOLD}{CYAN}{'Пароль':<18} {'Истекает':<14} {'Уст.':<6} {'Статус'}{NC}")
            lines.append("  " + "─" * 46)
            for pw, entry, expired in active_list:
                exp = entry.get("expires_at", 0)
                if exp == 0:
                    exp_str = "бессрочный"
                else:
                    dt = datetime.fromtimestamp(exp)
                    exp_str = dt.strftime("%d.%m.%Y")
                devs = len(entry.get("device_ids", []) or
                           ([entry["device_id"]] if entry.get("device_id") else []))
                max_d = entry.get("max_devices", 1) or 1
                deact = entry.get("is_deactivated", False)
                if deact:
                    status = f"{RED}отключён{NC}"
                elif expired:
                    status = f"{YELLOW}истёк{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                pw_short = pw[:16]
                lines.append(
                    f"  {CYAN}{pw_short:<18}{NC} {DIM}{exp_str:<14}{NC} {devs}/{max_d:<4} {status}"
                )
        else:
            lines.append(f"  {YELLOW}Временных паролей нет.{NC}")
            
        panel("🔑 УПРАВЛЕНИЕ ВРЕМЕННЫМИ ПАРОЛЯМИ", lines)
        
        options = [
            ("1", "➕ Создать временный пароль", ""),
            ("2", "🔗 Показать ссылку для пароля", ""),
            ("3", "❌ Удалить пароль", ""),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(options, "ПАРОЛИ")
        if choice == "0":
            break
        elif choice == "1":
            _create_password_wizard(state)
        elif choice == "2":
            _show_password_link_wizard(state, passwords)
        elif choice == "3":
            _delete_password_wizard(passwords)

def _create_password_wizard(state: AppState):
    clear()
    title("Создание временного пароля")
    
    raw_days = prompt("Дней действия (1-365)", default="30")
    days = int(raw_days) if raw_days.isdigit() else 30
    days = max(1, min(365, days))
    
    raw_devs = prompt("Макс. устройств (1-10)", default="1")
    max_devs = int(raw_devs) if raw_devs.isdigit() else 1
    max_devs = max(1, min(10, max_devs))
    
    vk_hash = prompt("VK хеш звонка (пропустить)").strip()
    
    data = _load_passwords()
    passwords = data.setdefault("passwords", {})
    if len(passwords) >= 10:
        error("Превышен лимит: максимум 10 паролей!")
        prompt("Нажмите Enter...")
        return
        
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    new_pass = ''.join(secrets.choice(chars) for _ in range(16))
    expires_at = int((datetime.now() + timedelta(days=days)).timestamp())
    
    passwords[new_pass] = {
        "device_ids": [],
        "max_devices": max_devs,
        "expires_at": expires_at,
        "down_bytes": 0,
        "up_bytes": 0,
        "vk_hash": vk_hash,
        "ports": "",
        "is_deactivated": False,
    }
    _save_passwords(data)
    _hot_reload()
    
    success("Пароль успешно создан и применён!")
    
    server_ip = state.network.server_ip or _get_server_ip()
    ps = get_protocol(state, "wdtt")
    dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
    
    vk_part = vk_hash if vk_hash else "ВК_ХЕШ"
    link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_part}"
        f"&workers=16&port={LOCAL_TUN_PORT}"
        f"&pass={new_pass}"
    )
    
    print()
    box(f" Временный пароль: {YELLOW}{new_pass}{NC}\n"
        f" Действует до:     {datetime.fromtimestamp(expires_at).strftime('%d.%m.%Y')}\n"
        f" Устройств:        {max_devs}\n\n"
        f" Ссылка qwdtt:// для клиента:\n\n{YELLOW}{link}{NC}",
        "ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ")
        
    _save_link_to_file(link, f"link_{new_pass[:8]}.txt")
    prompt("Нажмите Enter...")

def _show_password_link_wizard(state: AppState, passwords: dict):
    if not passwords:
        warn("Нет созданных паролей.")
        prompt("Нажмите Enter...")
        return
        
    clear()
    title("Показать ссылку для пароля")
    
    options = []
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        vk = passwords[pw].get("vk_hash", "") or "—"
        options.append((str(i), f"{pw[:16]}", f"хеш: {vk[:15]}"))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "ВЫБЕРИТЕ ПАРОЛЬ")
    if choice == "0" or not choice:
        return
        
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(pw_list):
            pw = pw_list[idx]
            entry = passwords[pw]
            server_ip = state.network.server_ip or _get_server_ip()
            ps = get_protocol(state, "wdtt")
            dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
            
            vk_hash = entry.get("vk_hash", "") or "ВК_ХЕШ"
            link = (
                f"qwdtt://config?name=qWDTT-{server_ip}"
                f"&peer={server_ip}:{dtls_port}"
                f"&hashes={vk_hash}"
                f"&workers=16&port={LOCAL_TUN_PORT}"
                f"&pass={pw}"
            )
            
            print()
            box(f" Пароль: {YELLOW}{pw}{NC}\n\n"
                f" Ссылка для клиента:\n\n{YELLOW}{link}{NC}",
                "ССЫЛКА ПОДКЛЮЧЕНИЯ")
            
            _save_link_to_file(link, f"link_{pw[:8]}.txt")
    except ValueError:
        error("Неверный ввод.")
        
    prompt("Нажмите Enter...")

def _delete_password_wizard(passwords: dict):
    if not passwords:
        warn("Нет созданных паролей.")
        prompt("Нажмите Enter...")
        return
        
    clear()
    title("Удалить временный пароль")
    
    options = []
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        options.append((str(i), f"{pw[:16]}", ""))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "УДАЛИТЬ ПАРОЛЬ")
    if choice == "0" or not choice:
        return
        
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(pw_list):
            pw = pw_list[idx]
            if confirm(f"Удалить пароль {pw[:8]}...?"):
                data = _load_passwords()
                if pw in data.get("passwords", {}):
                    del data["passwords"][pw]
                    _save_passwords(data)
                    _hot_reload()
                    success("Пароль успешно удалён!")
    except ValueError:
        error("Неверный ввод.")
        
    prompt("Нажмите Enter...")

# ══════════════════════════════════════════════════════════════════════════════
#  ОПЕРАЦИОННЫЕ ФУНКЦИИ
# ══════════════════════════════════════════════════════════════════════════════

def _show_main_link(state: AppState):
    clear()
    ps = get_protocol(state, "wdtt")
    dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
    main_pass = ps.config.get("main_password", "")
    server_ip = state.network.server_ip or _get_server_ip()
    
    qwdtt_link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes=ВК_ХЕШ"
        f"&workers=16&port={LOCAL_TUN_PORT}"
        f"&pass={main_pass}"
    )
    
    print()
    box(f" Ссылка qwdtt:// (Главный пароль):\n\n{YELLOW}{qwdtt_link}{NC}\n\n"
        f" Замените ВК_ХЕШ на хеш из ссылки vk.com/call/join/ХЕШ",
        "ГЛАВНАЯ ССЫЛКА")
        
    _save_link_to_file(qwdtt_link, "qwdtt_link.txt")
    prompt("Нажмите Enter...")

def _restart_service():
    info("Перезапускаю wdtt-server...")
    subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True)
    time.sleep(1.5)
    r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
    if r.stdout.strip() == "active":
        success("Сервис успешно перезапущен!")
    else:
        error("Ошибка перезапуска сервиса. Проверьте статус/логи.")
    prompt("Нажмите Enter...")

def _show_status_logs():
    clear()
    title("Статус и Логи qWDTT")
    
    r = subprocess.run(["systemctl", "status", SERVICE_NAME], capture_output=True, text=True)
    status_output = r.stdout or r.stderr or "Нет вывода"
    
    print(f"\n{CYAN}=== systemctl status wdtt ==={NC}\n")
    print(status_output)
    
    print(f"\n{CYAN}=== Последние 20 строк journalctl ==={NC}\n")
    r2 = subprocess.run(["journalctl", "-u", SERVICE_NAME, "-n", "20", "--no-pager"], capture_output=True, text=True)
    print(r2.stdout or r2.stderr or "Нет записей")
    
    prompt("Нажмите Enter...")

def _uninstall_wdtt(state: AppState, plugin):
    clear()
    title("Удаление qWDTT")
    warn("Это полностью удалит qWDTT с вашего сервера.")
    if confirm("Вы уверены, что хотите удалить qWDTT?"):
        info("Удаляю...")
        ok = orchestrator.uninstall_plugin(state, "wdtt")
        if ok:
            success("qWDTT успешно удалён с сервера.")
        else:
            error("Ошибка при удалении плагина.")
        prompt("Нажмите Enter...")

# ══════════════════════════════════════════════════════════════════════════════
#  СПРАВОЧНИК / ГАЙДЫ
# ══════════════════════════════════════════════════════════════════════════════

def _show_guide():
    while True:
        clear()
        title("Руководство по qWDTT")
        options = [
            ("1", "📱 Приложение на Android", ""),
            ("2", "🔑 Получение VK-хеша звонка", ""),
            ("3", "🤖 Настройка Telegram-бота", ""),
            ("0", "↩ Назад", "")
        ]
        choice = menu(options, "РУКОВОДСТВО")
        if choice == "0":
            break
        elif choice == "1":
            _guide_android()
        elif choice == "2":
            _guide_vk_hash()
        elif choice == "3":
            _guide_telegram()

def _guide_android():
    clear()
    print(f"""
  {BOLD}{CYAN}📱 ПРИЛОЖЕНИЕ qWDTT{NC}

  qWDTT — форк нетРКН с поддержкой WireGuard/TURN профилей и qwdtt:// ссылок.
  
  {BOLD}Скачать APK:{NC}
  Скачайте APK с официального релиза на GitHub:
  {YELLOW}https://github.com/SpaceNeuroX/proxy-turn-vk-android/releases{NC}
  
  Установите на устройство, разрешив установку из внешних источников.
  Требуется Android 8.0+.
""")
    prompt("Нажмите Enter...")

def _guide_vk_hash():
    clear()
    print(f"""
  {BOLD}{CYAN}🔑 ПОЛУЧЕНИЕ VK-ХЕША ЗВОНКА{NC}

  Хеш звонка — это часть ссылки-приглашения после /join/ в звонках ВКонтакте.
  
  {BOLD}Инструкция:{NC}
  1. В приложении VK перейдите в «Звонки» → «Создать звонок».
  2. Скопируйте ссылку-приглашение (вида https://vk.com/call/join/ХЕШ).
  3. Скопируйте часть после /join/ — это и есть ваш хеш.
  
  Вы можете указать до 4 хешей через запятую для балансировки нагрузки.
  Когда выходите из звонка, выбирайте «Просто выйти», а не «Завершить для всех».
""")
    prompt("Нажмите Enter...")

def _guide_telegram():
    clear()
    print(f"""
  {BOLD}{CYAN}🤖 НАСТРОЙКА TELEGRAM-БОТА{NC}

  Telegram-бот позволяет управлять паролями прямо из мессенджера без SSH.
  
  {BOLD}Инструкция:{NC}
  1. Напишите @BotFather в Telegram и создайте нового бота (/newbot).
  2. Получите Token вашего бота.
  3. Узнайте свой Chat ID через бота @userinfobot или аналогичные.
  4. Пропишите эти данные при установке/настройке qWDTT.
  
  {BOLD}Команды бота:{NC}
  • /new  — создать временный пароль
  • /list — список активных паролей и управление устройствами
""")
    prompt("Нажмите Enter...""")
