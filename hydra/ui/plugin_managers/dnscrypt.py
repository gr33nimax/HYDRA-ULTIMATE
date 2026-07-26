"""
hydra/plugins/dnscrypt/manager.py — TUI-консоль управления DNSCrypt-proxy.
"""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, DIM, WHITE, NC
)
def _get_current_server_names(app: ApplicationService) -> list[str]:
    return list(app.plugin_query("dnscrypt", "current_server_names"))


def _apply_server_names(
    names: list[str],
    app: ApplicationService,
) -> bool:
    return bool(
        app.plugin_action(
            "dnscrypt",
            "apply_server_names",
            names=names,
        ),
    )


def _fetch_resolver_list(
    app: ApplicationService,
) -> tuple[list[str], bool, str]:
    return app.plugin_query("dnscrypt", "resolver_catalog")


def _measure_all_latency(
    resolvers: list[str],
    app: ApplicationService,
) -> list[tuple[str, float]]:
    return list(
        app.plugin_query(
            "dnscrypt",
            "measure_resolvers",
            resolvers=resolvers,
        ),
    )


def _resolver_page_lines(
    resolvers: list[str],
    latency: dict[str, float],
    current: list[str],
    *,
    page: int,
    page_size: int,
) -> list[str]:
    start = page * page_size
    end = min(start + page_size, len(resolvers))
    total_pages = (len(resolvers) + page_size - 1) // page_size
    lines = [
        f"  Страница {page + 1} из {total_pages} "
        f"(показано {start + 1}-{end} из {len(resolvers)})",
        "  " + "─" * 50,
    ]
    for index in range(start, end):
        name = resolvers[index]
        milliseconds = latency.get(name)
        marker = f" {GREEN}← текущий{NC}" if name in current else ""
        if milliseconds is not None and milliseconds < 9999.0:
            color = (
                GREEN
                if milliseconds < 50
                else YELLOW if milliseconds < 150 else RED
            )
            value = f"{color}{milliseconds:.0f} мс{NC}{marker}"
        elif milliseconds is not None:
            value = f"{DIM}недоступен{NC}{marker}"
        else:
            value = f"{DIM}—{NC}{marker}"
        lines.append(
            f"  {WHITE}{index + 1:>3}.{NC} "
            f"{CYAN}{name:<30}{NC} {value}",
        )
    lines.extend([
        "  " + "─" * 50,
        "  Ввод номера через запятую (например: 1,3,7)",
        "  Ввод: [n] - след. страница, [p] - пред. страница, [0] - отмена",
    ])
    return lines


def _parse_resolver_selection(
    raw: str,
    ranked: list[str],
    available: list[str],
) -> tuple[list[str], list[str]]:
    chosen: list[str] = []
    errors: list[str] = []
    for part in (item.strip() for item in raw.split(",")):
        if not part:
            continue
        if part.isdigit():
            index = int(part)
            if 1 <= index <= len(ranked):
                name = ranked[index - 1]
                if name not in chosen:
                    chosen.append(name)
            else:
                errors.append(f"{part} (некорректный номер)")
        elif part in available and part not in chosen:
            chosen.append(part)
        else:
            errors.append(f"'{part}' (не найден)")
    return chosen, errors


def _confirm_resolver_selection(
    chosen: list[str],
    app: ApplicationService,
) -> bool:
    clear()
    lines = [
        f"Выбраны следующие резолверы ({len(chosen)} шт.):",
        "  " + "─" * 50,
    ]
    lines.extend(
        f"  {WHITE}{index:>2}.{NC} {CYAN}{name}{NC}"
        for index, name in enumerate(chosen, 1)
    )
    if len(chosen) == 1:
        lines.extend([
            "",
            f"  {YELLOW}⚠ Рекомендуется выбрать минимум 2 "
            f"для отказоустойчивости.{NC}",
        ])
    panel("✅ ПОДТВЕРЖДЕНИЕ ВЫБОРА", lines)
    if not confirm("Применить эти резолверы?"):
        return False

    info("Сохраняю server_names...")
    if _apply_server_names(chosen, app):
        success("Настройки сохранены!")
        app.monitoring.sleep(1)
        if app.admin.unit_active("dnscrypt-proxy"):
            success("DNSCrypt-proxy успешно запущен!")
            info("Тест DNS через 127.0.0.1:5300...")
            probes = app.plugin_query(
                "dnscrypt",
                "resolution_probe",
                domains=("google.com", "cloudflare.com", "github.com"),
            )
            for domain, query_time in probes:
                if query_time is None:
                    print(f"    {domain:<20} {RED}нет ответа{NC}")
                else:
                    color = GREEN if query_time < 50 else YELLOW
                    print(f"    {domain:<20} {color}{query_time} мс{NC}")
        else:
            error(
                "DNSCrypt-proxy не запустился! "
                "Проверьте логи: journalctl -u dnscrypt-proxy",
            )
    else:
        error("Не удалось сохранить настройки.")
    prompt("Нажмите Enter для продолжения")
    return True


def do_dnscrypt_selector(
    state: AppState,
    app: ApplicationService,
) -> None:
    clear()
    panel("🔍 ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ", [
        "Замеряет latency до всех доступных резолверов с этого сервера",
        "и показывает топ-100 по скорости. Выберите 2–3 резолвера —",
        "они будут прописаны в server_names и применены немедленно.",
        "────────────────────────────────────────────────────────",
        "Выбирайте исходя из географии VPS, а не личных предпочтений —",
        "быстрее будет тот, кто физически ближе к серверу."
    ])

    current = _get_current_server_names(app)
    if current:
        info(f"Текущие server_names: {', '.join(current)}")
    else:
        info("server_names не установлен (используется весь пул)")

    info("Получаю список резолверов...")
    resolvers, sorted_by_rtt, debug_info = _fetch_resolver_list(app)

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
    measured = _measure_all_latency(top_all, app)

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
        panel(
            "🔍 ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ",
            _resolver_page_lines(
                top,
                latency_map,
                current,
                page=page,
                page_size=page_size,
            ),
        )

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

        new_chosen, errors = _parse_resolver_selection(
            raw,
            top,
            resolvers,
        )

        if errors:
            warn(f"Ошибки: {', '.join(errors)}")
            app.monitoring.sleep(1.5)
            continue

        if not new_chosen:
            continue

        if _confirm_resolver_selection(new_chosen, app):
            return


def menu_dnscrypt(
    state: AppState,
    app: ApplicationService,
) -> None:
    state.protocols.setdefault("dnscrypt", PluginState())

    while True:
        clear()
        st = app.protocols.status("dnscrypt")
        current = _get_current_server_names(app)

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
            options.append(("1", "🔧 Установить", "Защищённый локальный DNS-резолвер"))
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
            if app.protocols.install(state, "dnscrypt"):
                success("DNSCrypt-proxy успешно установлен!")
            else:
                error("Ошибка при установке.")
            prompt("Нажмите Enter для продолжения")
            continue

        # ── Включение / Выключение ──
        elif choice == "1" and st.installed:
            if st.enabled:
                info("Выключаю DNSCrypt...")
                if app.protocols.disable(state, "dnscrypt"):
                    success("DNSCrypt успешно выключен.")
                else:
                    error("Ошибка при выключении.")
            else:
                info("Включаю DNSCrypt...")
                if app.protocols.enable(state, "dnscrypt"):
                    success("DNSCrypt успешно включен.")
                else:
                    error("Ошибка при включении.")
            prompt("Нажмите Enter для продолжения")

        # ── Выбор резолверов ──
        elif choice == "2" and st.installed:
            do_dnscrypt_selector(state, app)

        # ── Переустановка ──
        elif choice == "8" and st.installed:
            warn("ПЕРЕУСТАНОВКА DNSCRYPT!")
            if confirm("Продолжить?", default=False):
                info("Восстанавливаю установку с сохранением настроек...")
                if app.protocols.reinstall(state, "dnscrypt"):
                    success("Успешно переустановлено!")
                else:
                    error("Ошибка при переустановке.")
            prompt("Нажмите Enter для продолжения")

        # ── Удаление ──
        elif choice == "9" and st.installed:
            warn("ПОЛНОЕ УДАЛЕНИЕ DNSCRYPT!")
            if confirm("Вы уверены?", default=False):
                info("Удаляю...")
                if app.protocols.disable(state, "dnscrypt"):
                    app.protocols.uninstall(state, "dnscrypt")
                    success("DNSCrypt полностью удалён.")
                else:
                    error("Не удалось отключить DNSCrypt перед удалением.")
            prompt("Нажмите Enter для продолжения")
