"""
hydra/plugins/dnscrypt/manager.py — TUI-консоль управления DNSCrypt-proxy.
"""
from __future__ import annotations

import re
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hydra.core.state import AppState
from hydra.core.host import HOST
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC
)
import hydra.core.orchestrator as orchestrator
from hydra.plugins.dnscrypt.plugin import DNSCRYPT_CONF, DNSCRYPT_PORT, get_dnscrypt_bin


def _get_current_server_names() -> list[str]:
    if not DNSCRYPT_CONF.exists():
        return []
    try:
        content = DNSCRYPT_CONF.read_text(encoding="utf-8")
        m = re.search(r"^server_names\s*=\s*\[([^\]]+)\]", content, re.MULTILINE)
        if not m:
            return []
        return [s.strip().strip("'\"") for s in m.group(1).split(",") if s.strip()]
    except Exception:
        return []


def _apply_server_names(names: list[str]) -> bool:
    if not DNSCRYPT_CONF.exists():
        return False
    if not names or any(not re.fullmatch(r"[A-Za-z0-9._-]+", name) for name in names):
        return False
    try:
        previous = DNSCRYPT_CONF.read_bytes()
        content = DNSCRYPT_CONF.read_text(encoding="utf-8")
        names_str = ", ".join(f"'{n}'" for n in names)
        new_line = f"server_names = [{names_str}]"

        if re.search(r"^server_names\s*=", content, re.MULTILINE):
            content = re.sub(
                r"^server_names\s*=\s*\[.*?\]",
                new_line,
                content,
                count=1,
                flags=re.MULTILINE | re.DOTALL,
            )
        else:
            updated = re.sub(
                r"(^listen_addresses\s*=\s*\[.*?\]\n)",
                r"\1" + new_line + "\n",
                content,
                count=1,
                flags=re.MULTILINE,
            )
            content = updated if updated != content else new_line + "\n" + content

        HOST.atomic_write(DNSCRYPT_CONF, content)
        checked = HOST.run(
            [str(get_dnscrypt_bin()), "-check", "-config", str(DNSCRYPT_CONF)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if checked.returncode != 0:
            HOST.atomic_write(DNSCRYPT_CONF, previous)
            return False
        restarted = HOST.systemd("restart", "dnscrypt-proxy")
        if restarted.returncode != 0:
            HOST.atomic_write(DNSCRYPT_CONF, previous)
            HOST.systemd("restart", "dnscrypt-proxy")
            return False
        return True
    except Exception:
        try:
            if "previous" in locals():
                HOST.atomic_write(DNSCRYPT_CONF, previous)
        except Exception:
            pass
        return False


def _find_cache_dir() -> str:
    for p in [
        "/var/cache/dnscrypt-proxy",
        "/var/lib/dnscrypt-proxy",
        "/etc/dnscrypt-proxy",
        "/usr/local/etc/dnscrypt-proxy"
    ]:
        if (Path(p) / "public-resolvers.md").exists():
            return p
    return "/etc/dnscrypt-proxy"


def _fetch_resolver_list() -> tuple[list[str], bool, str]:
    debug_info = []
    try:
        # Check CACHE_PATHS presence
        for cp in [
            "/etc/dnscrypt-proxy/public-resolvers.md",
            "/var/cache/dnscrypt-proxy/public-resolvers.md",
            "/var/lib/dnscrypt-proxy/public-resolvers.md",
            "/usr/local/etc/dnscrypt-proxy/public-resolvers.md"
        ]:
            debug_info.append(f"Cache file {cp}: exists={Path(cp).exists()}")

        stamp_ips = _parse_resolver_ips_from_md()
        names = list(stamp_ips.keys())
        debug_info.append(f"Loaded {len(names)} resolvers directly from public-resolvers.md")
        if names:
            return names, False, "\n".join(debug_info)
    except Exception as e:
        debug_info.append(f"Error parsing public-resolvers.md: {e}")

    debug_info.append("public-resolvers.md cache is empty or not found")
    return [], False, "\n".join(debug_info)


def _parse_resolver_ips_from_md() -> dict[str, tuple[str, list[int]]]:
    import base64
    CACHE_PATHS = [
        Path("/etc/dnscrypt-proxy/public-resolvers.md"),
        Path("/var/cache/dnscrypt-proxy/public-resolvers.md"),
        Path("/var/lib/dnscrypt-proxy/public-resolvers.md"),
        Path("/usr/local/etc/dnscrypt-proxy/public-resolvers.md"),
    ]

    md_content = None
    for p in CACHE_PATHS:
        if p.exists():
            try:
                md_content = p.read_text(encoding="utf-8", errors="replace")
                break
            except Exception:
                pass

    result: dict[str, tuple[str, list[int]]] = {}
    if not md_content:
        return result

    def _decode_stamp(stamp_b64: str) -> tuple[str, int] | None:
        try:
            pad = 4 - len(stamp_b64) % 4
            if pad != 4:
                stamp_b64 += "=" * pad
            data = base64.urlsafe_b64decode(stamp_b64)
            if len(data) < 10:
                return None

            addr_len = data[9]
            if len(data) < 10 + addr_len:
                return None
            addr_raw = data[10:10 + addr_len].decode("utf-8", errors="replace").strip()

            if not addr_raw:
                return None

            port = 443
            ip = addr_raw

            if addr_raw.startswith("["):
                bracket_end = addr_raw.find("]")
                if bracket_end != -1:
                    ip = addr_raw[1:bracket_end]
                    rest = addr_raw[bracket_end + 1:]
                    if rest.startswith(":"):
                        try:
                            port = int(rest[1:])
                        except ValueError:
                            pass
            elif ":" in addr_raw:
                parts = addr_raw.rsplit(":", 1)
                ip = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    pass

            if not ip:
                return None

            return ip, port
        except Exception:
            return None

    current_name: str | None = None
    stamps_for_name: list[tuple[str, int]] = []

    def _flush(name: str, stamps: list[tuple[str, int]]) -> None:
        if not name or not stamps:
            return
        ip, port = stamps[0]
        ports_seen: list[int] = []
        for _, p in stamps:
            if p not in ports_seen:
                ports_seen.append(p)
        for fallback in [443, 853, 5353, 8443, 9953]:
            if fallback not in ports_seen:
                ports_seen.append(fallback)
        result[name] = (ip, ports_seen[:5])

    for line in md_content.splitlines():
        line = line.strip()
        if line.startswith("## "):
            if current_name is not None:
                _flush(current_name, stamps_for_name)
            current_name = line[3:].strip()
            stamps_for_name = []
            continue

        if line.startswith("sdns://") and current_name:
            stamp_b64 = line[7:]
            decoded = _decode_stamp(stamp_b64)
            if decoded:
                stamps_for_name.append(decoded)

    if current_name is not None:
        _flush(current_name, stamps_for_name)

    return result


def _measure_all_latency(resolvers: list[str]) -> list[tuple[str, float]]:
    stamp_ips = _parse_resolver_ips_from_md()

    def _ping_resolver(name: str) -> tuple[str, float]:
        entry = stamp_ips.get(name)
        if not entry:
            return name, 9999.0

        ip, ports = entry
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            for p in ports:
                try:
                    start = time.monotonic()
                    with socket.socket(family, socket.SOCK_STREAM) as s:
                        s.settimeout(2.0)
                        s.connect((ip, p))
                    ms = (time.monotonic() - start) * 1000
                    return name, round(ms, 1)
                except Exception:
                    continue
        except Exception:
            pass
        return name, 9999.0

    results: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_ping_resolver, name): name for name in resolvers}
        for future in as_completed(futures):
            results.append(future.result())

    reachable = sorted([(n, ms) for n, ms in results if ms < 9999.0], key=lambda x: x[1])
    unreachable = [(n, ms) for n, ms in results if ms >= 9999.0]

    unreachable_ordered = []
    reachable_names = {n for n, _ in reachable}
    for name in resolvers:
        if name not in reachable_names:
            unreachable_ordered.append((name, 9999.0))

    return reachable + unreachable_ordered


def do_dnscrypt_selector(state: AppState, plugin) -> None:
    clear()
    panel("🔍 ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ", [
        "Замеряет latency до всех доступных резолверов с этого сервера",
        "и показывает топ-100 по скорости. Выберите 2–3 резолвера —",
        "они будут прописаны в server_names и применены немедленно.",
        "────────────────────────────────────────────────────────",
        "Выбирайте исходя из географии VPS, а не личных предпочтений —",
        "быстрее будет тот, кто физически ближе к серверу."
    ])

    current = _get_current_server_names()
    if current:
        info(f"Текущие server_names: {', '.join(current)}")
    else:
        info("server_names не установлен (используется весь пул)")

    info("Получаю список резолверов...")
    resolvers, sorted_by_rtt, debug_info = _fetch_resolver_list()

    if not resolvers:
        warn("Список резолверов пуст. Возможно:")
        warn("  • DNSCrypt ещё не скачал public-resolvers.md (подождите минуту)")
        warn("  • Нет доступа к интернету с сервера")
        print(f"\n  {YELLOW}═══════════════ ОТЛАДОЧНЫЕ ДАННЫЕ ═══════════════{NC}")
        for line in debug_info.splitlines():
            print(f"  {DIM}{line}{NC}")
        print(f"  {YELLOW}═════════════════════════════════════════════════{NC}\n")
        prompt("Нажмите Enter для выхода")
        return

    top_all = resolvers[:100]

    info("Замеряю TCP latency для резолверов (параллельно, ~10-20 сек)...")
    measured = _measure_all_latency(top_all)

    reachable = [(n, ms) for n, ms in measured if ms < 9999.0]
    unreachable = [(n, ms) for n, ms in measured if ms >= 9999.0]

    if reachable or unreachable:
        top = [n for n, _ in reachable] + [n for n, _ in unreachable]
        latency_map = {n: ms for n, ms in measured}
    else:
        top = top_all
        latency_map = {}

    page = 0
    page_size = 20

    while True:
        clear()
        start = page * page_size
        end = min(start + page_size, len(top))
        total_pages = (len(top) + page_size - 1) // page_size

        status_lines = [
            f"  Страница {page + 1} из {total_pages} (показано {start + 1}-{end} из {len(top)})",
            "  " + "─" * 50
        ]

        for idx in range(start, end):
            name = top[idx]
            ms = latency_map.get(name)
            is_current = name in current
            marker = f" {GREEN}← текущий{NC}" if is_current else ""
            if ms is not None and ms < 9999.0:
                lat_color = GREEN if ms < 50 else YELLOW if ms < 150 else RED
                ms_text = f"{lat_color}{ms:.0f} мс{NC}{marker}"
            elif ms is not None:
                ms_text = f"{DIM}недоступен{NC}{marker}"
            else:
                ms_text = f"{DIM}—{NC}{marker}"

            status_lines.append(f"  {WHITE}{idx + 1:>3}.{NC} {CYAN}{name:<30}{NC} {ms_text}")

        status_lines.append("  " + "─" * 50)
        status_lines.append("  Ввод номера через запятую (например: 1,3,7)")
        status_lines.append("  Ввод: [n] - след. страница, [p] - пред. страница, [0] - отмена")

        panel("🔍 ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ", status_lines)

        raw = prompt("Выбор").strip()
        if not raw:
            continue

        rl = raw.lower()
        if rl == "0":
            return
        if rl == "n":
            if (page + 1) * page_size < len(top):
                page += 1
            continue
        if rl == "p":
            if page > 0:
                page -= 1
            continue

        # Парсим номера
        errors = []
        new_chosen = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(top):
                    name = top[idx - 1]
                    if name not in new_chosen:
                        new_chosen.append(name)
                else:
                    errors.append(f"{part} (некорректный номер)")
            else:
                if part in resolvers and part not in new_chosen:
                    new_chosen.append(part)
                else:
                    errors.append(f"'{part}' (не найден)")

        if errors:
            warn(f"Ошибки: {', '.join(errors)}")
            time.sleep(1.5)
            continue

        if not new_chosen:
            continue

        # Подтверждение
        clear()
        confirm_lines = [
            f"Выбраны следующие резолверы ({len(new_chosen)} шт.):",
            "  " + "─" * 50
        ]
        for i, name in enumerate(new_chosen, 1):
            confirm_lines.append(f"  {WHITE}{i:>2}.{NC} {CYAN}{name}{NC}")

        if len(new_chosen) == 1:
            confirm_lines.append("")
            confirm_lines.append(f"  {YELLOW}⚠ Рекомендуется выбрать минимум 2 для отказоустойчивости.{NC}")

        panel("✅ ПОДТВЕРЖДЕНИЕ ВЫБОРА", confirm_lines)

        if confirm("Применить эти резолверы?"):
            info("Сохраняю server_names...")
            if _apply_server_names(new_chosen):
                success("Настройки сохранены!")
                time.sleep(1)

                # Проверяем статус
                r = HOST.systemd("is-active", "dnscrypt-proxy")
                if r.returncode == 0:
                    success("DNSCrypt-proxy успешно запущен!")
                    info("Тест DNS через 127.0.0.1:5300...")
                    for domain in ("google.com", "cloudflare.com", "github.com"):
                        try:
                            r3 = HOST.run(
                                ["dig", f"@127.0.0.1", f"-p{DNSCRYPT_PORT}", domain,
                                 "+time=3", "+tries=1", "+noall", "+stats"],
                                text=True, timeout=5,
                            )
                            m2 = re.search(r"Query time:\s*(\d+)\s*msec", r3.stdout)
                            qt = m2.group(1) if m2 else None
                            if qt is not None:
                                color = GREEN if int(qt) < 50 else YELLOW
                                print(f"    {domain:<20} {color}{qt} мс{NC}")
                            else:
                                print(f"    {domain:<20} {RED}нет ответа{NC}")
                        except Exception:
                            print(f"    {domain:<20} {RED}ошибка{NC}")
                else:
                    error("DNSCrypt-proxy не запустился! Проверьте логи: journalctl -u dnscrypt-proxy")
            else:
                error("Не удалось сохранить настройки.")
            prompt("Нажмите Enter для продолжения")
            return


def menu_dnscrypt(state: AppState, plugin) -> None:
    ps = state.protocols.setdefault("dnscrypt", state.protocols.get("dnscrypt") or __import__("hydra.core.state").core.state.PluginState())

    while True:
        clear()
        st = plugin.status()
        current = _get_current_server_names()

        status_lines = []
        if not st.installed:
            status_lines.append(f"  Статус:      {RED}🔴 Не установлен{NC}")
        else:
            status_lines.append(f"  Статус:      {(GREEN+'🟢 Работает') if st.running else (RED+'🔴 Остановлен')}{NC}")
            status_lines.append(f"  Включён:     {GREEN if st.enabled else DIM}{'да' if st.enabled else 'нет'}{NC}")
            status_lines.append(f"  Порт:        {CYAN}{st.port}{NC}")
            if current:
                status_lines.append(f"  Резолверы:   {CYAN}{', '.join(current)}{NC}")
            else:
                status_lines.append(f"  Резолверы:   {YELLOW}используется весь пул{NC}")

        panel("🛡️ DNSCRYPT-PROXY CONTROL", status_lines)

        options = []
        if not st.installed:
            options.append(("1", "🔧 Установить", plugin.meta.description))
        else:
            options.append(("1", f"{'⏸️  Выключить' if st.enabled else '▶️  Включить'} DNSCrypt", "Переключить статус службы"))
            options.append(("2", "🔍 Выбор резолверов (latency)", "Выбрать оптимальные серверы DNS с замером пинга"))
            options.append(("-", "", ""))
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление с сервера"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, "УПРАВЛЕНИЕ DNSCRYPT")
        if choice == "0":
            break

        # ── Установка ──
        if choice == "1" and not st.installed:
            info("Устанавливаю DNSCrypt-proxy...")
            if orchestrator.install_plugin(state, plugin.meta.name):
                success("DNSCrypt-proxy успешно установлен!")
            else:
                error("Ошибка при установке.")
            prompt("Нажмите Enter для продолжения")
            continue

        # ── Включение / Выключение ──
        elif choice == "1" and st.installed:
            if st.enabled:
                info("Выключаю DNSCrypt...")
                if orchestrator.disable(state, "dnscrypt"):
                    success("DNSCrypt успешно выключен.")
                else:
                    error("Ошибка при выключении.")
            else:
                info("Включаю DNSCrypt...")
                if orchestrator.enable(state, "dnscrypt"):
                    success("DNSCrypt успешно включен.")
                else:
                    error("Ошибка при включении.")
            prompt("Нажмите Enter для продолжения")

        # ── Выбор резолверов ──
        elif choice == "2" and st.installed:
            do_dnscrypt_selector(state, plugin)

        # ── Переустановка ──
        elif choice == "8" and st.installed:
            warn("ПЕРЕУСТАНОВКА DNSCRYPT!")
            if confirm("Продолжить?", default=False):
                info("Восстанавливаю установку с сохранением настроек...")
                if plugin.repair_installation(enabled=st.enabled):
                    success("Успешно переустановлено!")
                else:
                    error("Ошибка при переустановке.")
            prompt("Нажмите Enter для продолжения")

        # ── Удаление ──
        elif choice == "9" and st.installed:
            warn("ПОЛНОЕ УДАЛЕНИЕ DNSCRYPT!")
            if confirm("Вы уверены?", default=False):
                info("Удаляю...")
                if orchestrator.disable(state, "dnscrypt"):
                    orchestrator.uninstall_plugin(state, plugin.meta.name)
                    success("DNSCrypt полностью удалён.")
                else:
                    error("Не удалось отключить DNSCrypt перед удалением.")
            prompt("Нажмите Enter для продолжения")
