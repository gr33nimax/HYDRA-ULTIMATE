#!/usr/bin/env python3
"""Purge remaining Xray code and patch HYDRA replacements in _core.py."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "vless_installer" / "_core.py"

sys.path.insert(0, str(ROOT / "tools"))
from purge_xray_core import remove_function  # noqa: E402

EXTRA_REMOVE = [
    "_fp_get_current", "_fp_patch_config", "_fp_install_cron", "_fp_remove_cron",
    "do_manage_fingerprint",
    "_unified_load_users", "_unified_save_users", "_unified_gen_link", "_unified_show_links",
    "do_manage_geo_update",
    "_patch_nginx_socket",
    "_import_users_only",
    "do_export_config", "do_import_config",
    "_uuid_rotate_now", "_uuid_install_cron", "do_manage_uuid_rotation",
    "_watchdog_install", "_watchdog_remove", "do_manage_watchdog",
    "do_export_client_config",
    "do_full_migration_export", "do_full_migration_import",
    "do_connection_audit",
    "do_manage_geoip_block",
    "_geoip_block_get_rules", "_geoip_apply_routing", "_geoip_set_allowlist",
    "_geoip_add_country_block", "_geoip_add_scanner_block", "_geoip_remove_all",
    "_as_normalize", "_as_validate", "_as_direct_file", "_as_direct_comment",
    "_as_direct_list_load", "_as_direct_list_save", "_as_direct_list_get_action",
    "_as_direct_save", "_as_direct_load_from_file", "_as_get_proxy_outbound_tag",
    "_as_direct_apply_to_xray", "_as_direct_remove_from_xray",
    "_as_direct_restore_if_needed", "_as_suggest_server_asn", "_as_direct_count_rules",
    "_as_direct_install_timer", "_as_direct_remove_timer", "_as_direct_timer_status",
    "_as_direct_cli_update", "_as_ask_action", "_as_action_label",
    "do_manage_as_direct",
]

HYDRA_HELPERS = '''
# --- HYDRA helpers (single-node, без Xray/cascade) -------------------------
def _nodes_from_state(state: dict) -> list:
    """Cascade nodes не используются в HYDRA."""
    return []


def _users_from_state() -> list[dict]:
    """Пользователи подписок из state.json."""
    if not STATE_FILE.exists():
        return []
    try:
        state = json.loads(STATE_FILE.read_text())
        out: list[dict] = []
        for email, meta in state.get("users", {}).items():
            row = {"email": email, "name": email}
            if isinstance(meta, dict):
                row.update(meta)
            out.append(row)
        return out
    except Exception:
        return []


_HYDRA_BACKUP_FILES = (
    STATE_FILE,
    Path("/var/lib/xray-installer/naiveproxy.json"),
    Path("/var/lib/xray-installer/mieru.json"),
    Path("/var/lib/xray-installer/sub_server.json"),
    Path("/var/lib/xray-installer/tg_bot.json"),
    Path("/var/lib/xray-installer/ingress_geoip.json"),
    Path("/var/lib/xray-installer/ipban.json"),
)


def _hydra_collect_backup_paths() -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = []
    for p in _HYDRA_BACKUP_FILES:
        if p.exists():
            items.append((p, p.name))
    sub_dir = Path("/var/lib/xray-installer/subscriptions")
    if sub_dir.is_dir():
        for f in sub_dir.glob("*.json"):
            items.append((f, f"subscriptions/{f.name}"))
    return items


def do_hydra_export_backup(encrypt: bool = False) -> None:
    """Архив state + конфигов HYDRA-стека."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = Path(f"/root/hydra-backup-{ts}.tar.gz")
    items = _hydra_collect_backup_paths()
    if not items:
        warn("Нет файлов для экспорта — сначала выполните установку HYDRA")
        return
    info(f"Экспорт HYDRA → {archive_path}")
    import tarfile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        manifest = []
        for src, arcname in items:
            dst = tmpdir / arcname
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest.append(arcname)
        (tmpdir / "MANIFEST.txt").write_text("\\n".join(manifest), encoding="utf-8")
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in tmpdir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tmpdir).as_posix())
    archive_path.chmod(0o600)
    success(f"Архив создан: {archive_path} ({len(items)} файлов)")
    if encrypt:
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для шифрования: ")
            pwd2 = getpass.getpass("  Повторите пароль: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
            pwd2 = input("  Повторите: ").strip()
        if pwd != pwd2 or not pwd:
            warn("Пароли не совпали — архив оставлен без шифрования")
            return
        enc = _backup_encrypt(archive_path, pwd)
        if enc:
            archive_path.unlink(missing_ok=True)
            success(f"Зашифровано: {enc}")


def do_hydra_import_backup() -> None:
    """Восстановление state/конфигов HYDRA из tar.gz."""
    raw = input("  Путь к архиву (.tar.gz или .gz.enc): ").strip()
    ap = Path(raw)
    if not ap.exists():
        warn(f"Файл не найден: {ap}")
        return
    if ap.suffix == ".enc":
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для расшифровки: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
        dec_path = ap.with_suffix("").with_suffix(".tar.gz")
        if not _backup_decrypt(ap, pwd, dec_path):
            return
        ap = dec_path
    import tarfile
    import tempfile
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with tarfile.open(ap, "r:gz") as tar:
            tar.extractall(tmpdir)
        restored = 0
        for f in tmpdir.rglob("*"):
            if not f.is_file() or f.name == "MANIFEST.txt":
                continue
            rel = f.relative_to(tmpdir)
            if str(rel).startswith("subscriptions/"):
                dest = Path("/var/lib/xray-installer") / rel
            else:
                dest = Path("/var/lib/xray-installer") / f.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            dest.chmod(0o600)
            restored += 1
    success(f"Восстановлено файлов: {restored}")
    warn("Перезапустите сервисы HYDRA при необходимости (Naive, Mieru, sub-server, боты)")


def do_full_diagnostic() -> None:
    """Диагностика HYDRA-стека без Xray."""
    print()
    _box_top("HYDRA — полная диагностика")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    _box_row(f"  {DIM}{ts}{NC}")
    _box_row(f"  {BOLD}Сервисы:{NC}")
    hydra_svcs = (
        "caddy-naive", "mita", "hydra-sub-server",
        "hydra-tg-bot", "hydra-tg-admin", "dnscrypt-proxy",
    )
    for svc in hydra_svcs:
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        st = r.stdout.strip()
        if st == "active":
            _box_row(f"  {GREEN}●{NC} {svc:<24} {GREEN}активен{NC}")
        elif st == "inactive":
            _box_row(f"  {DIM}○{NC} {svc:<24} {DIM}не запущен{NC}")
        else:
            _box_row(f"  {RED}✗{NC} {svc:<24} {RED}{st or 'нет'}{NC}")
    _box_row()
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
            dom = st.get("sub_domain") or st.get("domain", "")
            users_n = len(st.get("users", {}))
            _box_row(f"  {BOLD}State:{NC} домен={dom or '—'}  пользователей={users_n}")
        except Exception as e:
            _box_row(f"  {RED}state.json: {e}{NC}")
    else:
        _box_row(f"  {YELLOW}state.json не найден{NC}")
    _box_row()
    _box_row(f"  {BOLD}Сеть:{NC}")
    try:
        verify_connectivity()
    except Exception as e:
        warn(f"verify_connectivity: {e}")
    _box_row()
    try:
        do_dns_leak_test()
    except Exception:
        pass
    _box_bottom()

'''


def replace_function(src: str, name: str, new_body: str) -> str:
    pat = re.compile(rf"^def {re.escape(name)}\([^)]*\)[^:]*:\n", re.MULTILINE)
    m = pat.search(src)
    if not m:
        return src
    rest = src[m.end():]
    nxt = re.search(r"^(?:def |# ={10,})", rest, re.MULTILINE)
    end = m.end() + (nxt.start() if nxt else len(rest))
    return src[:m.start()] + new_body.strip() + "\n\n\n" + src[end:]


def patch(src: str, old: str, new: str, *, count: int = 1) -> str:
    if old not in src:
        print(f"  [skip] pattern not found ({old[:60]}...)")
        return src
    return src.replace(old, new, count)


def main() -> None:
    src = CORE.read_text(encoding="utf-8")
    removed = 0
    for name in EXTRA_REMOVE:
        new = remove_function(src, name)
        if new != src:
            removed += 1
            src = new
    print(f"Removed {removed} extra functions")

    if "def _nodes_from_state" not in src:
        src = patch(
            src,
            "def command_exists(cmd: str) -> bool:\n    return shutil.which(cmd) is not None\n",
            "def command_exists(cmd: str) -> bool:\n    return shutil.which(cmd) is not None\n"
            + HYDRA_HELPERS,
        )

    src = patch(
        src,
        """def _on_exit() -> None:
    global INSTALL_STARTED, STAGE_XRAY_DONE, STAGE_NGINX_DONE
    # Если установка завершена успешно — ничего не делаем
    if INSTALL_COMPLETED:
        return
    # Если установка ещё не начиналась (выход из меню) — ничего не делаем
    if not INSTALL_STARTED:
        return
    print()
    print(f"{RED}[ERROR]{NC} Скрипт завершился с ошибкой.")
    print(f"{YELLOW}[WARN]{NC}  Система может быть в неполном состоянии.")
    if shutil.which("ufw"):
        _run(["ufw", "allow", "22/tcp", "comment", "SSH (emergency restore)"],
             check=False, quiet=True)
    if STAGE_XRAY_DONE:
        _run(["systemctl", "stop",    "xray"], check=False, quiet=True)
        _run(["systemctl", "disable", "xray"], check=False, quiet=True)
    if STAGE_NGINX_DONE:
        _run(["systemctl", "stop", "nginx"], check=False, quiet=True)
    print(f"{YELLOW}[WARN]{NC}  Полный лог: {LOG_FILE}")""",
        """def _on_exit() -> None:
    global INSTALL_STARTED
    if INSTALL_COMPLETED or not INSTALL_STARTED:
        return
    print()
    print(f"{RED}[ERROR]{NC} Скрипт завершился с ошибкой.")
    print(f"{YELLOW}[WARN]{NC}  Система может быть в неполном состоянии.")
    if shutil.which("ufw"):
        _run(["ufw", "allow", "22/tcp", "comment", "SSH (emergency restore)"],
             check=False, quiet=True)
    print(f"{YELLOW}[WARN]{NC}  Полный лог: {LOG_FILE}")""",
    )

    src = patch(
        src,
        """        cfg_path = None
        for p in (Path("/etc/xray/config.json"), Path("/usr/local/etc/xray/config.json")):
            if p.exists():
                cfg_path = p
                break
        if cfg_path:
            try:
                with cfg_path.open() as f:
                    c = json.load(f)
                clients = c.get("inbounds", [{}])[0].get("settings", {}).get("clients", [])
                for cl in clients:
                    email = cl.get("email")
                    if email and email not in sub_tokens:
                        sub_tokens[email] = gen_uuid()
                        changed = True
            except Exception:
                pass
            
        # NaiveProxy users""",
        """        for email in state.get("users", {}):
            if email and email not in sub_tokens:
                sub_tokens[email] = gen_uuid()
                changed = True

        # NaiveProxy users""",
    )

    src = patch(src, "        CHAIN_NODES = _nodes_from_state(state)", "        CHAIN_NODES = []")

    src = patch(src, "            users   = _users_load()", "            users   = _users_from_state()")

    src = patch(
        src,
        '    _box_top("VLESS Quick Status")',
        '    _box_top("HYDRA Quick Status")',
    )
    src = patch(
        src,
        '    for svc in ("xray", "nginx", "dnscrypt-proxy"):',
        '    for svc in ("caddy-naive", "mita", "hydra-sub-server", "dnscrypt-proxy"):',
    )

    # Убрать VLESS/AWG-exit блок из quick status — заменить протокол секцию
    old_proto = """            _proto = _qs.get("protocol_mode", "reality")
            _dom   = _qs.get("domain", "")
            _port  = _qs.get("server_port", 443)
            _flow  = _qs.get("xtls_flow", "xtls-rprx-vision")
            if _proto == "reality":
                _proto_label = f"VLESS+REALITY  flow={_flow or 'none'}"
            else:
                _proto_label = "VLESS+xHTTP+TLS"
            _box_row(f"  {BOLD}Конфиг:{NC}")
            _box_row(f"  {CYAN}⚙{NC}  {'Протокол:':<22} {_proto_label}")
            if _dom:
                _box_row(f"  {CYAN}🌐{NC} {'Домен/порт:':<22} {_dom}:{_port}")
            # ── AWG-туннель ──────────────────────────────────────────────────
            if _qs.get("awg_exit_enabled") and _qs.get("install_mode") == "B":
                _awg_host = _qs.get("awg_exit_host", "")
                _awg_port = _qs.get("awg_exit_port", 51820)
                _box_row(f"  {CYAN}🔌{NC} {'AWG exit-VPS:':<22} {_awg_host}:{_awg_port}/udp")
                _r_if = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
                _awg_col = GREEN if _r_if.returncode == 0 else RED
                _awg_status = "активен" if _r_if.returncode == 0 else "НЕ ПОДНЯТ"
                _box_row(f"  {_awg_col}🔌{NC} {'awg0:':<22} {_awg_col}{_awg_status}{NC}")
            _box_row()"""
    new_proto = """            _dom = _qs.get("sub_domain") or _qs.get("domain", "")
            _users_n = len(_qs.get("users", {}))
            _box_row(f"  {BOLD}HYDRA:{NC}")
            _box_row(f"  {CYAN}👥{NC} {'Пользователей:':<22} {_users_n}")
            if _dom:
                _box_row(f"  {CYAN}🌐{NC} {'Домен подписок:':<22} {_dom}")
            _box_row()"""
    src = patch(src, old_proto, new_proto)

  # Убрать AS-маршруты из quick status
    src = patch(
        src,
        """    # ── AS-маршруты (патч: задача #5) ────────────────────────────────────────
    try:
        _as_qs_entries = _as_direct_list_load()
        if _as_qs_entries:
            _box_row()
            _box_row(f"  {BOLD}AS-маршруты ({len(_as_qs_entries)}):{NC}")
            for _ase in _as_qs_entries:
                _box_row(f"  {CYAN}⇢{NC}  {BOLD}{_ase['asn']}{NC}  [{_as_action_label(_ase.get('action', 'direct'))}]")
    except Exception:
        pass

    _box_bottom()""",
        "    _box_bottom()",
    )

    # Диагностическое меню
    src = patch(
        src,
        """        _box_item("1", f"📊 Live Traffic Dashboard  {DIM}(реальное время){NC}")
        _box_item("2", f"📈 История трафика по дням  {DIM}(ASCII-гистограмма){NC}")
        _box_item("3", f"📡 Тест качества соединения  {DIM}(TTFB){NC}")
        _box_item("4", f"🔍 Аудит подключений  {DIM}(кто / когда / откуда){NC}")
        _box_item("5", "📋 Лог изменений конфигурации")
        _box_item("6", f"🩺 Ежедневный Health-отчёт  {DIM}(cron 08:00){NC}")
        _box_item("7", "🩺 Полная диагностика одной кнопкой")
        _box_item("8", f"💻 Системный дашборд  {DIM}(CPU / RAM / Disk){NC}")""",
        """        _box_item("1", f"📡 Тест качества соединения  {DIM}(TTFB){NC}")
        _box_item("2", "📋 Лог изменений конфигурации")
        _box_item("3", f"🩺 Ежедневный Health-отчёт  {DIM}(cron 08:00){NC}")
        _box_item("4", "🩺 Полная диагностика HYDRA")
        _box_item("5", f"💻 Системный дашборд  {DIM}(CPU / RAM / Disk){NC}")""",
    )
    src = patch(
        src,
        """        _box_item("P", f"🔧 Патч Stats API  {DIM}(починить статистику трафика){NC}")
        _box_item("N", f"🔍 DNS Leak Test  {DIM}(проверить утечку DNS-запросов){NC}")""",
        """        _box_item("N", f"🔍 DNS Leak Test  {DIM}(проверить утечку DNS-запросов){NC}")""",
    )
    src = patch(
        src,
        """        if ch == "1":
            do_live_traffic_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_traffic_history()
        elif ch == "3":
            do_connection_quality_test()
        elif ch == "4":
            do_connection_audit()
        elif ch == "5":
            do_view_changes_log()
        elif ch == "6":
            do_manage_health_report()
        elif ch == "7":
            do_full_diagnostic()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            do_system_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")""",
        """        if ch == "1":
            do_connection_quality_test()
        elif ch == "2":
            do_view_changes_log()
        elif ch == "3":
            do_manage_health_report()
        elif ch == "4":
            do_full_diagnostic()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            do_system_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")""",
    )
    src = patch(
        src,
        """        elif ch.lower() == "p":
            do_patch_stats_api()
        elif ch.lower() == "n":""",
        """        elif ch.lower() == "n":""",
    )
    src = patch(
        src,
        """            svcs = []
            r = _run(["systemctl", "is-enabled", "dnscrypt-proxy"],
                     capture=True, check=False)
            if r.returncode == 0:
                svcs = ["dnscrypt-proxy"]
            for svc in svcs:""",
        """            svcs = ["caddy-naive", "mita", "hydra-sub-server", "dnscrypt-proxy"]
            for svc in svcs:""",
    )

    # Миграция → HYDRA backup
    src = patch(
        src,
        """        if ch == "1":
            do_full_migration_export()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_full_migration_import()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            do_export_config()
            input(f"{BLUE}Нажмите Enter...{NC}")""",
        """        if ch == "1":
            do_hydra_export_backup(encrypt=True)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_hydra_import_backup()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            do_hydra_export_backup(encrypt=False)
            input(f"{BLUE}Нажмите Enter...{NC}")""",
    )

    # do_manage_backup menu
    src = patch(src, "            do_export_config(encrypt=False)", "            do_hydra_export_backup(encrypt=False)")
    src = patch(src, "            do_export_config(encrypt=True)", "            do_hydra_export_backup(encrypt=True)")
    src = patch(src, "            do_import_config()", "            do_hydra_import_backup()")

    # Безопасность: GeoIP Block → ingress
    src = patch(
        src,
        """        _box_item("1", f"🛡️  GeoIP Block  {DIM}(allowlist / blocklist / сканеры){NC}")""",
        """        _box_item("1", f"🛡️  Ingress GeoIP  {DIM}(блок входящих из РФ — iptables){NC}")""",
    )
    src = patch(src, "            do_manage_geoip_block()", "            do_manage_ingress_geoip()")

    # Планировщик: убрать Xray-задачи
    src = patch(
        src,
        """        {
            "id":       "geo",
            "emoji":    "🗺️",
            "label":    "Обновление GeoIP / GeoSite",
            "schedule": "Вс 03:00",
            "cron":     "/etc/cron.d/xray-geo-update",
            "unit":     None,
            "log":      "/var/log/xray-geo-update.log",
            "fn_on":    lambda: _run(["/usr/local/bin/xray-geo-update.sh"],
                                     check=False, quiet=True) if Path("/usr/local/bin/xray-geo-update.sh").exists()
                                else do_manage_geo_update(),
            "fn_toggle": None,  # управляется через do_manage_geo_update
            "configure": do_manage_geo_update,
        },
        {
            "id":       "watchdog",
            "emoji":    "🐕",
            "label":    "Watchdog (авторестарт Xray)",
            "schedule": "каждые 2 мин",
            "cron":     None,
            "unit":     "xray-watchdog.timer",
            "log":      "/var/log/xray-watchdog.log",
            "configure": do_manage_watchdog,
        },
        {""",
        """        {""",
    )
    src = patch(
        src,
        """        {
            "id":       "fp",
            "emoji":    "🔑",
            "label":    "Ротация Fingerprint",
            "schedule": "настраивается",
            "cron":     f"/etc/cron.d/{_FP_CRON_TAG}",
            "unit":     None,
            "log":      None,
            "configure": do_manage_fingerprint,
        },
        {
            "id":       "uuid",
            "emoji":    "🔄",
            "label":    "Ротация UUID",
            "schedule": "настраивается",
            "cron":     f"/etc/cron.d/{_UUID_CRON_TAG}",
            "unit":     None,
            "log":      None,
            "configure": do_manage_uuid_rotation,
        },
        {""",
        """        {""",
    )

    # do_share_config_server — подписки вместо VLESS
    old_share = """    # Собираем VLESS-ссылки
    links: list[dict] = []
    try:
        users = _users_load()
        if users:
            for u in users[:5]:
                lnks = _unified_show_links(u, print_output=False)
                if lnks:
                    links.append({"name": u.get("name", "user"), "links": lnks})
        if not links:
            domain   = state.get("domain", "")
            vuuid    = state.get("uuid", "")
            pub_key  = state.get("public_key", "")
            short_id = state.get("short_id", "")
            fp       = state.get("fingerprint", "chrome")
            port     = state.get("server_port", 443)
            proto    = state.get("protocol_mode", "reality")
            # SNI: при Mode B + AWG — домен маскировки, иначе собственный домен.
            # Ключ "sni" не сохраняется в state.json, поэтому читаем reality_dest.
            _sc_install_mode = state.get("install_mode", "A")
            _sc_awg = state.get("awg_exit_enabled", False) and _sc_install_mode == "B"
            _sc_reality_dest = state.get("reality_dest", "")
            if proto == "reality" and _sc_awg and _sc_reality_dest:
                sni = _sc_reality_dest
            else:
                sni = domain
            if proto == "reality":
                link = (f"vless://{vuuid}@{domain}:{port}"
                        f"?encryption=none&flow=xtls-rprx-vision"
                        f"&security=reality&sni={sni}"
                        f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                        f"&type=tcp#VLESS-Reality")
            else:
                xhttp_path = urllib.parse.quote(state.get("xhttp_path", "/"), safe="")
                link = (f"vless://{vuuid}@{domain}:{port}"
                        f"?encryption=none&security=tls&sni={domain}"
                        f"&fp={fp}&type=http&path={xhttp_path}#VLESS-xHTTP")
            links.append({"name": "default", "links": [link]})
    except Exception as e:
        _box_warn(f"Ошибка сборки ссылок: {e}")
        return"""
    new_share = """    links: list[dict] = []
    try:
        sub_domain = state.get("sub_domain") or state.get("domain", "")
        sub_tokens = state.get("sub_tokens", {})
        for email, token in list(sub_tokens.items())[:8]:
            if sub_domain and token:
                url = f"https://{sub_domain}/sub/{token}"
                links.append({"name": email, "links": [url]})
        if not links and sub_domain:
            links.append({
                "name": "info",
                "links": [f"https://{sub_domain}/ — портал подписок HYDRA"],
            })
    except Exception as e:
        _box_warn(f"Ошибка сборки ссылок: {e}")
        return"""
    src = patch(src, old_share, new_share)

    CORE.write_text(src, encoding="utf-8")
    print(f"Patched {CORE}")
    print(f"Lines: {len(src.splitlines())}")


if __name__ == "__main__":
    main()
