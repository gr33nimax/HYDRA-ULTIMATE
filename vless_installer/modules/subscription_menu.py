"""
Subscription management TUI (menu section 2).
Extracted from vless_installer/_core.py (Phase 4).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import threading
from datetime import datetime
from pathlib import Path


class _LazyCore:
    """Late-bind to vless_installer._core (avoids circular import at load time)."""
    _mod = None

    def _m(self):
        if self._mod is None:
            import vless_installer._core as m
            self._mod = m
        return self._mod

    def __getattr__(self, name: str):
        return getattr(self._m(), name)


core = _LazyCore()


def ensure_subscription_tokens() -> None:
    """Убедиться, что у всех существующих пользователей есть подписочный токен в state.json."""
    if not core.STATE_FILE.exists():
        return
    try:
        state = json.loads(core.STATE_FILE.read_text())
        sub_tokens = state.setdefault("sub_tokens", {})
        changed = False
        
        for email in state.get("users", {}):
            if email and email not in sub_tokens:
                sub_tokens[email] = core.gen_uuid()
                changed = True

        # NaiveProxy users
        naive_users = []
        np_state_file = Path("/var/lib/xray-installer/naiveproxy.json")
        if np_state_file.exists():
            try:
                naive_users = json.loads(np_state_file.read_text(encoding="utf-8")).get("users", [])
            except Exception:
                pass
        for nu in naive_users:
            username = nu.get("username")
            if username and username not in sub_tokens:
                sub_tokens[username] = core.gen_uuid()
                changed = True
                
        # Mieru users
        mieru_users = []
        mieru_state_file = Path("/var/lib/xray-installer/mieru.json")
        if mieru_state_file.exists():
            try:
                mieru_users = json.loads(mieru_state_file.read_text(encoding="utf-8")).get("users", [])
            except Exception:
                pass
        for mu in mieru_users:
            username = mu.get("username")
            if username and username not in sub_tokens:
                sub_tokens[username] = core.gen_uuid()
                changed = True
                
        main_email = state.get("email") or "admin"
        if main_email and main_email not in sub_tokens:
            sub_tokens[main_email] = state.get("uuid") or core.gen_uuid()
            changed = True
            
        if changed:
            core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception:
        pass


def _setup_subscription_domain_ssl() -> None:
    print()
    core._box_top("НАСТРОЙКА ДОМЕНА + SSL")
    core._box_row(f"  {core.YELLOW}Внимание:{core.NC} Будет выполнен выпуск SSL-сертификата Let's Encrypt.")
    core._box_row("  Для этого порт 80 должен быть свободен. Скрипт автоматически")
    core._box_row("  остановит Caddy / Nginx на время выпуска и запустит обратно.")
    core._box_bottom()
    
    new_domain = input(f"{core.CYAN}Введите домен для подписок (например, sub.yourdomain.com):{core.NC} ").strip()
    if not new_domain:
        core.warn("Домен не введен. Отмена.")
        time.sleep(1.5)
        return
        
    certbot_bin = next(
        (p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
         if p.exists()), None
    )
    if not certbot_bin:
        core.warn("certbot не найден. Пожалуйста, установите certbot на сервере.")
        time.sleep(2)
        return

    # Останавливаем веб-серверы
    nginx_was_active = False
    caddy_was_active = False

    try:
        r = subprocess.run(["systemctl", "is-active", "nginx"], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            core.info("Временная остановка Nginx...")
            subprocess.run(["systemctl", "stop", "nginx"], check=False)
            nginx_was_active = True
    except Exception:
        pass

    try:
        r = subprocess.run(["systemctl", "is-active", "caddy"], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            core.info("Временная остановка Caddy...")
            subprocess.run(["systemctl", "stop", "caddy"], check=False)
            caddy_was_active = True
    except Exception:
        pass

    core.info(f"Запуск certbot для домена {new_domain}...")
    try:
        r = subprocess.run([
            str(certbot_bin), "certonly", "--standalone",
            "-d", new_domain,
            "--non-interactive", "--agree-tos",
            "-m", f"admin@{new_domain}",
            "--keep-until-expiring"
        ], capture_output=True, text=True)
        certbot_ok = (r.returncode == 0)
    except Exception as e:
        certbot_ok = False
        core.warn(f"Ошибка вызова certbot: {e}")

    # Запускаем веб-серверы обратно
    if nginx_was_active:
        core.info("Запуск Nginx...")
        subprocess.run(["systemctl", "start", "nginx"], check=False)
    if caddy_was_active:
        core.info("Запуск Caddy...")
        subprocess.run(["systemctl", "start", "caddy"], check=False)

    if certbot_ok:
        # Проверяем файлы
        cert_file = Path(f"/etc/letsencrypt/live/{new_domain}/fullchain.pem")
        key_file = Path(f"/etc/letsencrypt/live/{new_domain}/privkey.pem")
        if cert_file.exists() and key_file.exists():
            state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
            state["sub_domain"] = new_domain
            core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            core.success(f"SSL-сертификат успешно получен для домена {new_domain}!")
            
            # Переустанавливаем сервис подписок, чтобы обновить домен и порт
            sub_port = state.get("sub_port", 9443)
            core.info("Перезапуск службы подписок с новым SSL-сертификатом...")
            from vless_installer.modules.sub_server import install_sub_service
            install_sub_service("0.0.0.0", sub_port)
            try:
                from vless_installer.modules.naiveproxy import sync_caddy_config
                sync_caddy_config()
            except Exception:
                pass
        else:
            core.warn("Certbot сообщил об успехе, но файлы сертификата не найдены по стандартному пути.")
    else:
        err_msg = r.stderr or r.stdout or "Неизвестная ошибка"
        core.warn(f"Не удалось получить SSL-сертификат:\n{err_msg}")

    time.sleep(3.5)


def _add_subscription_user() -> None:
    print()
    core._box_top("ДОБАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПОДПИСОК")
    core._box_row()
    core._box_bottom()
    
    while True:
        new_email = input(f"{core.CYAN}Введите имя/email нового пользователя:{core.NC} ").strip()
        if not new_email:
            core.warn("Имя не может быть пустым")
            continue
        if ' ' in new_email:
            core.warn("Имя не должно содержать пробелов")
            continue
            
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
        sub_tokens = state.setdefault("sub_tokens", {})
        if new_email in sub_tokens:
            core.warn(f"Пользователь '{new_email}' уже зарегистрирован в подписках")
            continue
        break
        
    try:
        from vless_installer.modules.user_lifecycle import sync_user_lifecycle
        sync_user_lifecycle(new_email, "add")
        core.success(f"Пользователь '{new_email}' успешно добавлен в систему подписок и все VPN-службы.")
    except Exception as e:
        core.warn(f"Ошибка при добавлении пользователя: {e}")
        
    state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    users_db = state.get("users", {})
    token = users_db.get(new_email, {}).get("token", "")
    
    # Сразу показываем ссылки
    sub_domain = state.get("sub_domain", "")
    domain = sub_domain or state.get("domain", "") or core.get_server_ip("4")
    port_suffix = ""
    base_url = f"https://{domain}{port_suffix}/sub/{token}"
    
    print()
    core._box_top(f"ССЫЛКИ ДЛЯ {new_email}")
    core._box_row(f"  {core.BOLD}Токен:{core.NC} {token}")
    core._box_sep()
    core._box_row(f"  {core.CYAN}Base64:{core.NC} {base_url}")
    core._box_bottom()
    
    input(f"\n{core.BLUE}Нажмите Enter для продолжения...{core.NC}")


def _delete_subscription_user() -> None:
    state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    sub_tokens = state.get("sub_tokens", {})
    if not sub_tokens:
        core.warn("Нет зарегистрированных пользователей подписок")
        time.sleep(1.5)
        return
        
    print()
    core._box_top("УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПОДПИСОК")
    users_list = list(sub_tokens.keys())
    for idx, name in enumerate(users_list, 1):
        core._box_row(f"  [{idx}] {name}")
    core._box_bottom()
    
    choice = input(f"{core.CYAN}Выберите номер или введите email для удаления:{core.NC} ").strip()
    if not choice:
        core.warn("Отменено")
        return
        
    target = None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(users_list):
            target = users_list[idx]
    if not target:
        if choice in sub_tokens:
            target = choice
            
    if not target:
        core.warn(f"Пользователь '{choice}' не найден")
        time.sleep(1.5)
        return
        
    ans = input(f"{core.YELLOW}Вы уверены, что хотите удалить пользователя {target}? [y/N]:{core.NC} ").strip().lower()
    if ans == "y":
        try:
            from vless_installer.modules.user_lifecycle import sync_user_lifecycle
            sync_user_lifecycle(target, "delete")
            core.success(f"Пользователь '{target}' удален из системы подписок и всех VPN-служб")
        except Exception as e:
            core.warn(f"Ошибка при удалении пользователя: {e}")
    else:
        core.info("Отменено")
    time.sleep(1.5)


def _change_subscription_port() -> None:
    try:
        new_port_str = input(f"{core.CYAN}Введите новый порт сервера подписок (1-65535, по умолчанию 9443):{core.NC} ").strip()
        new_port = int(new_port_str) if new_port_str else 9443
        if not (1 <= new_port <= 65535):
            raise ValueError
        
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
        state["sub_port"] = new_port
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        core.success(f"Порт изменен на {new_port}")
        
        # Проверяем, активен ли сервис подписок
        sub_svc_active = False
        try:
            r = subprocess.run(["systemctl", "is-active", "vless-sub"], capture_output=True, text=True)
            sub_svc_active = (r.stdout.strip() == "active")
        except Exception:
            pass

        if sub_svc_active:
            core.info("Перезапуск службы с новым портом...")
            from vless_installer.modules.sub_server import install_sub_service
            install_sub_service("0.0.0.0", new_port)
            try:
                from vless_installer.modules.naiveproxy import sync_caddy_config
                sync_caddy_config()
            except Exception:
                pass
    except ValueError:
        core.warn("Некорректный порт")
    except Exception as e:
        core.warn(f"Ошибка изменения porta: {e}")
    time.sleep(2)


def do_update_all_user_configs() -> None:
    """Проверяет пользователей подписок и создает конфигурации в NaiveProxy, Mieru и AmneziaWG."""
    print()
    core._box_top("СИНХРОНИЗАЦИЯ И ОБНОВЛЕНИЕ КОНФИГУРАЦИЙ")
    core._box_row()
    
    state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    sub_tokens = state.get("sub_tokens", {})
    if not sub_tokens:
        core._box_warn("Нет зарегистрированных пользователей подписок.")
        core._box_bottom()
        input(f"\n{core.BLUE}Нажмите Enter...{core.NC}")
        return

    # Проверяем, какие протоколы установлены в принципе
    np_installed = False
    try:
        from vless_installer.modules.naiveproxy import _is_installed as np_is_installed
        np_installed = np_is_installed()
    except Exception:
        pass
        
    mieru_installed = False
    try:
        from vless_installer.modules.mieru import _is_installed as mieru_is_installed
        mieru_installed = mieru_is_installed()
    except Exception:
        pass

    awg_installed = False
    try:
        from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists
        awg_installed = awg_exists()
    except Exception:
        pass

    core._box_info("Статус установленных протоколов на сервере:")
    core._box_row(f"  NaiveProxy: {'🟢 установлен' if np_installed else '🔴 не установлен'}")
    core._box_row(f"  Mieru:      {'🟢 установлен' if mieru_installed else '🔴 не установлен'}")
    core._box_row(f"  AmneziaWG:  {'🟢 установлен' if awg_installed else '🔴 не установлен'}")
    core._box_sep()

    changes_made = 0
    
    for email in sub_tokens.keys():
        core._box_info(f"Проверка пользователя {email}:")
        
        # 1. NaiveProxy
        if np_installed:
            try:
                from vless_installer.modules.naiveproxy import add_user_noninteractive as np_add
                res = np_add(email)
                if res:
                    core._box_ok(f"  NaiveProxy: создан новый аккаунт")
                    changes_made += 1
                else:
                    core._box_row(f"  NaiveProxy: уже существует")
            except Exception as e:
                core._box_warn(f"  NaiveProxy: ошибка создания: {e}")
        else:
            core._box_row("  NaiveProxy: пропущено (протокол не установлен)")

        # 2. Mieru
        if mieru_installed:
            try:
                from vless_installer.modules.mieru import add_user_noninteractive as mieru_add
                res = mieru_add(email)
                if res:
                    core._box_ok(f"  Mieru: создан новый аккаунт")
                    changes_made += 1
                else:
                    core._box_row(f"  Mieru: уже существует")
            except Exception as e:
                core._box_warn(f"  Mieru: ошибка создания: {e}")
        else:
            core._box_row("  Mieru: пропущено (протокол не установлен)")

        # 3. AmneziaWG
        if awg_installed:
            try:
                from vless_installer.modules.amnezia_vpn import ensure_awg_user
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', email)
                if not username_clean:
                    core._box_warn(f"  AmneziaWG: имя пользователя '{email}' недопустимо для AWG")
                else:
                    created, msg = ensure_awg_user(username_clean)
                    if created:
                        core._box_ok(f"  AmneziaWG: создан новый аккаунт")
                        changes_made += 1
                    else:
                        if "уже существует" in msg:
                            core._box_row(f"  AmneziaWG: уже существует")
                        else:
                            core._box_warn(f"  AmneziaWG: {msg}")
            except Exception as e:
                core._box_warn(f"  AmneziaWG: ошибка создания: {e}")
        else:
            core._box_row("  AmneziaWG: пропущено (протокол не установлен)")
        core._box_sep()

    if changes_made > 0:
        core.success("Все отсутствующие конфигурации успешно созданы!")
    else:
        core.info("Все конфигурации пользователей уже актуальны, изменений не требуется.")
        
    core._box_bottom()
    input(f"\n{core.BLUE}Нажмите Enter для продолжения...{core.NC}")


def do_subscription_menu() -> None:
    """Интерактивное меню для управления подписками пользователей."""
    ensure_subscription_tokens()

    while True:
        os.system("clear")
        
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
        users_db = state.get("users", {})
        _ttl_expiring = sum(
            1 for r in users_db.values()
            if r.get("expires_at")
            and core._ttl_expires_within_hours(r.get("expires_at"), 24)
            and not core._ttl_is_expired(r.get("expires_at"))
        )
        _ttl_badge = (
            f"  {core.YELLOW}⚠ {_ttl_expiring} истекают < 24ч{core.NC}" if _ttl_expiring else ""
        )

        core._box_top("📋 УПРАВЛЕНИЕ ПОДПИСКАМИ")
        core._box_row(f"  {core.DIM}Управление системой подписок пользователей{core.NC}")
        core._box_sep()

        sub_svc_active = False
        try:
            r = subprocess.run(["systemctl", "is-active", "vless-sub"], capture_output=True, text=True)
            sub_svc_active = (r.stdout.strip() == "active")
        except Exception:
            pass

        sub_domain = state.get("sub_domain", "")
        sub_port = state.get("sub_port", 9443)
        domain = sub_domain or state.get("domain", "") or core.get_server_ip("4")

        # Проверка SSL-сертификата
        ssl_status = f"{core.YELLOW}не найден{core.NC}"
        if sub_domain:
            cert_file = Path(f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem")
            key_file = Path(f"/etc/letsencrypt/live/{sub_domain}/privkey.pem")
            if cert_file.exists() and key_file.exists():
                ssl_status = f"{core.GREEN}активен (OK){core.NC}"
            else:
                ssl_status = f"{core.RED}ошибка (сертификаты не найдены){core.NC}"

        svc_status = f"{core.GREEN}активен{core.NC}" if sub_svc_active else f"{core.YELLOW}не активен{core.NC}"
        port_suffix = ""

        core._box_row(f"  Сервис подписок:  {svc_status}")
        core._box_row(f"  Домен подписок:   {sub_domain if sub_domain else f'{core.YELLOW}не настроен{core.NC}'}")
        core._box_row(f"  Порт подписок:    {sub_port}")
        core._box_row(f"  SSL-сертификат:   {ssl_status}")
        if sub_domain:
            core._box_row(f"  Внешний URL:      https://{domain}{port_suffix}/sub/<токен>")
        else:
            core._box_row(f"  Внешний URL:      (необходима настройка домена)")
            
        core._box_sep()

        core._box_item("1", "⚙️ Настроить сервис подписок (Домен + SSL)")
        core._box_item("2", f"{'Выключить' if sub_svc_active else 'Включить'} сервис подписок")
        core._box_sep()
        core._box_item("3", "👤 Добавить пользователя подписок")
        core._box_item("4", "❌ Удалить пользователя подписок")
        core._box_item("5", "🔗 Получить ссылки подписок для пользователя")
        core._box_item("6", "🔄 Перегенерировать токен пользователя")
        core._box_item("7", f"🔌 Изменить порт подписок {core.DIM}(текущий: {sub_port}){core.NC}")
        core._box_item("8", "📊 Лимиты трафика на пользователя")
        core._box_item(
            "9",
            f"⏱  Временные пользователи (TTL)"
            f"  {core.DIM}({sum(1 for u in users_db.values() if u.get('expires_at'))} записей){core.NC}{_ttl_badge}"
        )
        core._box_item("10", "🔄 Синхронизировать и обновить все конфигурации")
        core._box_row()
        core._box_item_exit("0", "← Назад")
        core._box_bottom()

        try:
            ch = input(f"{core.CYAN}Выбор:{core.NC} ").strip()
        except KeyboardInterrupt:
            break

        if ch in ("0", "q", "Q", ""):
            break

        elif ch == "1":
            _setup_subscription_domain_ssl()

        elif ch == "2":
            if sub_svc_active:
                core.info("Отключение службы подписок...")
                try:
                    from vless_installer.modules.sub_server import uninstall_sub_service
                    uninstall_sub_service()
                    try:
                        from vless_installer.modules.naiveproxy import sync_caddy_config
                        sync_caddy_config()
                    except Exception:
                        pass
                    core.uninstall_sync_agent()
                    core.success("Служба подписок отключена")
                except Exception as e:
                    core.warn(f"Ошибка отключения: {e}")
            else:
                core.info("Включение службы подписок...")
                try:
                    from vless_installer.modules.sub_server import install_sub_service
                    install_sub_service("0.0.0.0", sub_port)
                    try:
                        from vless_installer.modules.naiveproxy import sync_caddy_config
                        sync_caddy_config()
                    except Exception:
                        pass
                    core.install_sync_agent()
                    core.success("Служба подписок включена")
                except Exception as e:
                    core.warn(f"Ошибка включения: {e}")
            time.sleep(2)

        elif ch == "3":
            _add_subscription_user()

        elif ch == "4":
            _delete_subscription_user()

        elif ch == "5":
            _show_user_subscription_links()

        elif ch == "6":
            _regenerate_user_token()

        elif ch == "7":
            _change_subscription_port()

        elif ch == "8":
            core.do_manage_traffic_limits()

        elif ch == "9":
            core.do_manage_ttl_users()

        elif ch == "10":
            do_update_all_user_configs()

        elif ch in ("a", "A"):
            _ensure_awg_for_user()


def _ensure_awg_for_user() -> None:
    """Добавляет AWG-пользователя из подписочного списка если ещё нет."""
    users = _get_all_sub_users()
    if not users:
        core.warn("Пользователи не найдены")
        input(f"{core.BLUE}Нажмите Enter...{core.NC}")
        return

    os.system("clear")
    core._box_top("🛱  HYDRA → AmneziaWG: Добавить AWG-пользователя")
    core._box_row(f"  {core.DIM}Пользователь будет добавлен в AmneziaWG через Docker если ещё не существует{core.NC}")
    core._box_sep()
    for i, u in enumerate(users, 1):
        core._box_item(f"{i}", u.get("email", "?"))
    core._box_item_exit("0", "← Отмена")
    core._box_bottom()

    raw = input(f"{core.CYAN}Номер (Enter = все сразу):{core.NC} ").strip()
    if raw in ("0", "q", "Q"):
        return

    targets = []
    if raw == "":
        # Всем подряд
        targets = [u["email"] for u in users]
    elif raw.isdigit() and 1 <= int(raw) <= len(users):
        targets = [users[int(raw) - 1]["email"]]
    else:
        targets = [raw]

    try:
        from vless_installer.modules.amnezia_vpn import ensure_awg_user
    except ImportError as e:
        core.warn(f"Не удалось загрузить модуль amnezia_vpn: {e}")
        input(f"{core.BLUE}Нажмите Enter...{core.NC}")
        return

    print()
    created = 0
    for email in targets:
        username = email.split("@")[0] if "@" in email else email
        ok, msg = ensure_awg_user(username)
        if ok:
            core.success(f"✅ {email}: {msg}")
            created += 1
        else:
            core.info(f"ℹ️  {email}: {msg}")

    print()
    if created:
        core.success(f"Создано AWG-пользователей: {created}")
    else:
        core.info("Все пользователи уже имеют AWG-профиль")
    input(f"{core.BLUE}Нажмите Enter...{core.NC}")


def _get_all_sub_users() -> list[dict]:
    """Возвращает список пользователей HYDRA из state, NaiveProxy и Mieru."""
    users = []
    seen = set()

    # Из state.json
    if core.STATE_FILE.exists():
        try:
            state = json.loads(core.STATE_FILE.read_text(encoding="utf-8"))
            
            # NaiveProxy users
            naive_users = []
            np_state_file = Path("/var/lib/xray-installer/naiveproxy.json")
            if np_state_file.exists():
                try:
                    naive_users = json.loads(np_state_file.read_text(encoding="utf-8")).get("users", [])
                except Exception:
                    pass
            for nu in naive_users:
                username = nu.get("username")
                if username and username not in seen:
                    users.append({"email": username, "id": "NaiveProxy User", "source": "NaiveProxy"})
                    seen.add(username)
                    
            # Mieru users
            mieru_users = []
            mieru_state_file = Path("/var/lib/xray-installer/mieru.json")
            if mieru_state_file.exists():
                try:
                    mieru_users = json.loads(mieru_state_file.read_text(encoding="utf-8")).get("users", [])
                except Exception:
                    pass
            for mu in mieru_users:
                username = mu.get("username")
                if username and username not in seen:
                    users.append({"email": username, "id": "Mieru User", "source": "Mieru"})
                    seen.add(username)
                    
            # Из существующих токенов подписок
            sub_tokens = state.get("sub_tokens", {})
            for email in sub_tokens.keys():
                if email and email not in seen:
                    users.append({"email": email, "id": "Token only", "source": "Subscription"})
                    seen.add(email)
        except Exception:
            pass
            
    return users


def _show_user_subscription_links() -> None:
    users = _get_all_sub_users()
    core._box_top("СПИСОК ПОЛЬЗОВАТЕЛЕЙ ПОДПИСОК")
    if not users:
        core._box_row(f"  {core.DIM}Пользователи не найдены.{core.NC}")
        core._box_bottom()
        time.sleep(1.5)
        return
    else:
        core._box_row(f"  {'N':<4} {'Email/имя':<30} {'Идентификатор/Тип':<30} {'Источник':<20}")
        core._box_bottom()
        print("  " + "─" * 90)
        for i, u in enumerate(users, 1):
            print(f"  {i:<4} {u['email']:<30} {u['id']:<30} {u['source']:<20}")
            
    print()
    target = input(f"{core.CYAN}Email пользователя (или порядковый номер):{core.NC} ").strip()
    if not target:
        core.warn("Отмена")
        return

    found = None
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(users):
            found = users[idx]
    if not found:
        found = next((u for u in users if u["email"] == target or u["id"] == target), None)

    if not found:
        core.warn(f"Пользователь '{target}' не найден")
        time.sleep(1.5)
        return

    email = found["email"]
    state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
    sub_tokens = state.setdefault("sub_tokens", {})
    token = sub_tokens.get(email)

    if not token:
        token = core.gen_uuid()
        sub_tokens[email] = token
        state["sub_tokens"] = sub_tokens
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    sub_domain = state.get("sub_domain", "")
    sub_port = state.get("sub_port", 9443)
    domain = sub_domain or state.get("domain", "") or core.get_server_ip("4")
    port_suffix = ""
    base_url = f"https://{domain}{port_suffix}/sub/{token}"

    while True:
        os.system("clear")
        core._box_top(f"ПОДПИСКИ ПОЛЬЗОВАТЕЛЯ {email}")
        core._box_row(f"  {core.BOLD}Токен:{core.NC} {token}")
        core._box_sep()
        core._box_row("  Вставьте эту ссылку в клиент (v2rayNG, Hiddify, Nekobox):")
        core._box_row()
        core._box_row(f"  {core.CYAN}Base64 подписка (мобильная){core.NC} (v2rayNG, Shadowrocket, Hiddify):")
        _box_link(base_url)
        core._box_row()
        core._box_row(f"  {core.CYAN}PC подписка (для NekoBox PC / NyameBox){core.NC}:")
        _box_link(f"{base_url}/pc")
        core._box_sep()
        core._box_item("1", "📱 Показать QR-код для мобильной подписки")
        core._box_item("2", "💻 Показать QR-код для ПК подписки")
        core._box_row()
        core._box_item_exit("0", "← Назад")
        core._box_bottom()

        try:
            choice = input(f"{core.CYAN}Выбор:{core.NC} ").strip()
        except KeyboardInterrupt:
            break
        if choice in ("0", ""):
            break
        elif choice == "1":
            _show_qr(base_url, f"{email} Base64 Sub", f"/root/sub_base64_qr_{email}.png")
            input(f"{core.BLUE}Нажмите Enter...{core.NC}")
        elif choice == "2":
            _show_qr(f"{base_url}/pc", f"{email} PC Sub", f"/root/sub_pc_qr_{email}.png")
            input(f"{core.BLUE}Нажмите Enter...{core.NC}")


def _regenerate_user_token() -> None:
    users = _get_all_sub_users()
    core._box_top("СПИСОК ПОЛЬЗОВАТЕЛЕЙ ПОДПИСОК")
    if not users:
        core._box_row(f"  {core.DIM}Пользователи не найдены.{core.NC}")
        core._box_bottom()
        time.sleep(1.5)
        return
    else:
        core._box_row(f"  {'N':<4} {'Email/имя':<30} {'Идентификатор/Тип':<30} {'Источник':<20}")
        core._box_bottom()
        print("  " + "─" * 90)
        for i, u in enumerate(users, 1):
            print(f"  {i:<4} {u['email']:<30} {u['id']:<30} {u['source']:<20}")
            
    print()
    target = input(f"{core.CYAN}Email пользователя для сброса токена (или номер):{core.NC} ").strip()
    if not target:
        core.warn("Отмена")
        return

    found = None
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(users):
            found = users[idx]
    if not found:
        found = next((u for u in users if u["email"] == target or u["id"] == target), None)

    if not found:
        core.warn(f"Пользователь '{target}' не найден")
        time.sleep(1.5)
        return

    email = found["email"]
    ans = input(f"{core.YELLOW}Вы уверены, что хотите перегенерировать токен для {email}? Старая ссылка перестанет работать! [y/N]:{core.NC} ").strip().lower()
    if ans == "y":
        state = json.loads(core.STATE_FILE.read_text()) if core.STATE_FILE.exists() else {}
        sub_tokens = state.setdefault("sub_tokens", {})
        new_token = core.gen_uuid()
        sub_tokens[email] = new_token
        state["sub_tokens"] = sub_tokens
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        core.success(f"Токен для {email} успешно обновлен")
    else:
        core.info("Отменено")
    time.sleep(2)

# =============================================================================
#  ГЕНЕРАЦИЯ ССЫЛОК + QR
# =============================================================================
def _show_qr(link: str, label: str, png_path: str) -> None:
    """Выводит QR-код внутри рамки бокса."""
    print()
    core._box_top(f"QR-код [{label}]")
    core._box_row(f"  {core.CYAN}Отсканируйте в v2rayNG / Hiddify / Nekobox:{core.NC}")
    core._box_sep()

    qrencode = shutil.which("qrencode")
    if qrencode:
        # Выводим QR в терминал — каждая строка через core._box_row
        import subprocess as _sp
        # ГОЛУБОЙ QR: используем ANSI256 foreground (цвет модулей) через
        # --foreground / --background если qrencode >= 4.1, иначе оборачиваем
        # строки вывода в ANSI-escape для голубого цвета.
        _QR_COLOR = "\033[96m"   # bright cyan (ANSI 96)
        _QR_RESET = "\033[0m"
        try:
            _qr_proc = _sp.run(
                [qrencode, "-t", "ANSIUTF8", "-m", "1",
                 "--foreground=00BFFF", "--background=000000",
                 "--strict-version", link],
                capture_output=True, text=True
            )
            _qr_lines = _qr_proc.stdout.splitlines()
        except Exception:
            _qr_lines = []
        if not _qr_lines:
            # fallback: пробуем без --foreground (старые версии qrencode)
            try:
                _qr_proc = _sp.run(
                    [qrencode, "-t", "ANSIUTF8", "-m", "1", link],
                    capture_output=True, text=True
                )
                _qr_lines = _qr_proc.stdout.splitlines()
            except Exception:
                _qr_lines = []
        for _ql in _qr_lines:
            # Вставляем QR-строку внутрь рамки с отступом.
            # Если qrencode не поддержал --foreground, оборачиваем в core.CYAN escape.
            if _QR_COLOR not in _ql and "\033[" not in _ql:
                core._box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            else:
                core._box_row(f"  {_ql}")
        # Сохраняем PNG
        r = core._run([qrencode, "-t", "PNG", "-o", png_path, "-s", "8", "-m", "4", link],
                 check=False, quiet=True)
        core._box_sep()
        if r.returncode == 0:
            core._box_ok(f"QR PNG сохранён: {png_path}")
        else:
            core._box_warn(f"Не удалось сохранить QR PNG: {png_path}")
    else:
        # Fallback: python3-qrcode
        try:
            import qrcode  # type: ignore
            import io as _io
            qr = qrcode.QRCode(border=1)
            qr.add_data(link)
            qr.make(fit=True)
            # Захватываем ASCII-вывод
            _buf = _io.StringIO()
            import sys as _sys
            _old_stdout = _sys.stdout
            _sys.stdout = _buf
            qr.print_ascii(invert=True)
            _sys.stdout = _old_stdout
            _QR_COLOR = "\033[96m"
            _QR_RESET = "\033[0m"
            for _ql in _buf.getvalue().splitlines():
                core._box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            img = qr.make_image(fill_color='#00BFFF', back_color='black')
            img.save(png_path)
            core._box_sep()
            core._box_ok(f"QR PNG сохранён: {png_path}")
        except ImportError:
            core._box_warn("python3-qrcode не установлен: pip3 install qrcode[pil]")
        except Exception as e:
            core._box_warn(f"Ошибка QR: {e}")

    core._box_bottom()
