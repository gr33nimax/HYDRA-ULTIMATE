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
from hydra.plugins.warp.plugin import DEFAULT_WARP_DOMAINS, WGCF_PROFILE
from hydra.plugins.warp.clash_import import (
    ClashImportError, WARP_CONFIGS_DIR, WARP_ULTIMATE_BUNDLE, WARP_ULTIMATE_SOURCE,
    discover_warp_yaml_sources, import_clash_warp_bundle, load_or_refresh_warp_bundle,
)
from hydra.plugins.warp.routing_catalog import build_routing_catalog, category_target


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


def _ultimate_endpoint_options(bundle: dict | None) -> list[tuple[str, str]]:
    if not bundle:
        return []
    return [
        (str(item["tag"]), str(item["name"]))
        for item in bundle.get("endpoints", [])
        if item.get("tag") and item.get("name")
    ]


def _remove_legacy_yaml_routes(ps) -> bool:
    """Drop routes created by the retired Clash rule-provider importer."""
    list_targets = ps.config.setdefault("list_targets", {})
    legacy_keys = [key for key in list_targets if key.startswith("yaml:")]
    for key in legacy_keys:
        list_targets.pop(key, None)
    return bool(legacy_keys)


def _compact_destination_options(plugin, ps, bundle: dict | None) -> list[tuple[str, str]]:
    """Return friendly destinations, prioritising locations chosen by the user."""
    endpoint_options = _ultimate_endpoint_options(bundle)
    endpoint_tags = {tag for tag, _label in endpoint_options}
    selected = ps.config.get("ultimate_selected_tag")
    labels = dict(endpoint_options)
    favourite_tags = [
        tag for tag in ps.config.get("ultimate_route_tags", []) if tag in endpoint_tags
    ]
    if not favourite_tags and selected in endpoint_tags:
        favourite_tags = [selected]
    available = dict(plugin.available_destinations())
    result = [("direct", "Напрямую — IP этого сервера")]
    if "warp_ultimate_auto" in available:
        result.append(("warp_ultimate_auto", "Автовыбор — самая быстрая локация"))
    for tag, label in endpoint_options:
        if tag in favourite_tags:
            result.append((tag, f"{label} — WARP-локация"))
    for tag, label in available.items():
        if tag in endpoint_tags or tag in ("direct", "warp_ultimate", "warp_ultimate_auto", "warp"):
            continue
        result.append((tag, f"{label} — отдельный профиль"))
    if "warp" in available:
        result.append(("warp", "Cloudflare WARP — стандартный профиль"))
    # Keep the old selector visible only while a pre-2.3 route still uses it.
    if "warp_ultimate" in ps.config.get("list_targets", {}).values():
        selected_label = labels.get(selected, endpoint_options[0][1] if endpoint_options else "не выбрана")
        result.append(("warp_ultimate", f"Текущая локация — {selected_label} (старый маршрут)"))
    if endpoint_options and len(favourite_tags) < len(endpoint_options):
        result.append(("__ultimate_location__", "Другая WARP-локация…"))
    return result


def _choose_destination(title: str, options: list[tuple[str, str]], bundle: dict | None) -> str | None:
    menu_options = [
        (str(index), label, "Использовать для этой категории")
        for index, (tag, label) in enumerate(options, 1)
    ]
    menu_options.append((str(len(options) + 1), "Не маршрутизировать", "Убрать отдельное правило для категории"))
    menu_options.append(("0", "Отмена", ""))
    choice = menu(menu_options, title)
    if choice == "0" or not choice.isdigit():
        return None
    index = int(choice) - 1
    if index == len(options):
        return "none"
    if not 0 <= index < len(options):
        return None
    tag = options[index][0]
    if tag != "__ultimate_location__":
        return tag

    endpoint_options = _ultimate_endpoint_options(bundle)
    nested = [(str(i), label, "WARP-локация") for i, (_tag, label) in enumerate(endpoint_options, 1)]
    nested.append(("0", "Назад", ""))
    nested_choice = menu(nested, "ВЫБЕРИТЕ КОНКРЕТНУЮ WARP-ЛОКАЦИЮ")
    if not nested_choice.isdigit() or nested_choice == "0":
        return None
    nested_index = int(nested_choice) - 1
    return endpoint_options[nested_index][0] if 0 <= nested_index < len(endpoint_options) else None


def _menu_route_locations(state: AppState, ps, bundle: dict) -> None:
    """Choose the small set of locations displayed in everyday routing menus."""
    endpoint_options = _ultimate_endpoint_options(bundle)
    valid_tags = {tag for tag, _label in endpoint_options}
    selected = {
        tag for tag in ps.config.get("ultimate_route_tags", []) if tag in valid_tags
    }
    if not selected and endpoint_options:
        selected.add(ps.config.get("ultimate_selected_tag", endpoint_options[0][0]))
    while True:
        options = []
        for index, (tag, label) in enumerate(endpoint_options, 1):
            marker = "✓" if tag in selected else " "
            options.append((str(index), f"[{marker}] {label}", "Показывать в выборе направления"))
        options.append(("a", "✓ Выбрать все", "Показывать все локации"))
        options.append(("c", "Очистить выбор", "Оставить только автовыбор и прямое подключение"))
        options.append(("0", "Готово", "Сохранить выбор"))
        choice = menu(options, "МОИ WARP-ЛОКАЦИИ")
        if choice == "0":
            ps.config["ultimate_route_tags"] = [
                tag for tag, _label in endpoint_options if tag in selected
            ]
            save_state(state)
            return
        if choice == "a":
            selected = set(valid_tags)
        elif choice == "c":
            selected.clear()
        elif choice.isdigit() and 1 <= int(choice) <= len(endpoint_options):
            tag = endpoint_options[int(choice) - 1][0]
            selected.remove(tag) if tag in selected else selected.add(tag)


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
        custom_profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
        yaml_sources = discover_warp_yaml_sources()
        discovery_error = ""
        try:
            ultimate_bundle = load_or_refresh_warp_bundle()
        except ClashImportError as exc:
            ultimate_bundle = None
            discovery_error = str(exc)
        destination_options = _compact_destination_options(plugin, ps, ultimate_bundle)
        destinations = [tag for tag, _label in destination_options if not tag.startswith("__")]

        # Читаем списки
        local_lists = ps.config.setdefault("local_lists", {})
        list_targets = ps.config.setdefault("list_targets", {})
        if _remove_legacy_yaml_routes(ps):
            save_state(state)

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
            if ultimate_bundle:
                endpoint_count = len(ultimate_bundle.get("endpoints", []))
                endpoint_labels = dict(_ultimate_endpoint_options(ultimate_bundle))
                favourite_labels = [
                    endpoint_labels[tag] for tag in ps.config.get("ultimate_route_tags", [])
                    if tag in endpoint_labels
                ]
                selected_text = ", ".join(favourite_labels) if favourite_labels else "не выбраны"
                status_lines.append(f"  • WARP-локации:  {MAGENTA}{endpoint_count} доступно; мои: {selected_text}{NC}")

            status_lines.append("  " + "─" * 45)

            status_lines.append(f"  {BOLD}Маршрутизация по категориям:{NC}")
            from hydra.plugins.warp.plugin import EXTERNAL_LISTS
            categories = build_routing_catalog(EXTERNAL_LISTS, local_lists)
            destination_labels = dict(destination_options)
            active_routes = 0
            for category in categories:
                target = category_target(category, list_targets)
                if target == "none":
                    continue
                active_routes += 1
                label = "несколько направлений" if target == "mixed" else destination_labels.get(target, target)
                target_color = GREEN if target not in ("direct", "mixed") else YELLOW
                status_lines.append(f"  • {category.label:<26} → {target_color}{label}{NC}")
            if active_routes == 0:
                status_lines.append(f"  {YELLOW}Нет активных маршрутов. Настройте их ниже.{NC}")

        panel("🌐 УПРАВЛЕНИЕ WARP ROUTING & RELAYS", status_lines)

        options = []
        if not st.installed and not custom_profiles:
            options.append(("1", "🔧 Установить Cloudflare WARP (WGCF)", "Скачать и настроить локальный профиль по умолчанию"))
            options.append(("4", "📍 Локации и конфигурация", "Загрузить конфиг и выбрать WARP-локации"))
        else:
            options.append(("1", f"{'⏸️  Выключить' if st.enabled else '▶️  Включить'} WARP", "Переключить статус службы в Sing-Box"))
            options.append(("2", "📝 Свои домены и IP", "Необязательно: добавить собственную категорию"))
            options.append(("3", "🔀 Категории и направления", "Например: блокировки → Нидерланды, РФ-сервисы → Россия"))
            options.append(("4", "📍 Локации и конфигурация", "Загрузить конфиг и выбрать используемые локации"))
            options.append(("5", "🔄 Обновить категории", "Скачать свежие правила для настроенных категорий"))
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
            _menu_routing_rules(state, ps, destination_options, ultimate_bundle)

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
        
        status_lines = [f"  {BOLD}Свои категории доменов и IP:{NC}"]
        
        if not local_lists:
            status_lines.append(f"  {DIM}Нет созданных локальных списков.{NC}")
        else:
            for idx, (name, val) in enumerate(local_lists.items(), 1):
                domains_cnt = len(val.get("domains", []))
                ips_cnt = len(val.get("ips", []))
                status_lines.append(f"  {idx}. {BOLD}{name:<20}{NC} {domains_cnt} доменов · {ips_cnt} IP")

        panel("📝 СВОИ ДОМЕНЫ И IP", status_lines)

        options = [
            ("1", "➕ Создать локальный список", "Создать новую группу доменов/IP"),
            ("2", "📝 Редактировать локальный список", "Добавить/удалить домены и IP в локальном списке"),
            ("3", "🗑️  Удалить локальный список", "Удалить пользовательскую группу"),
            ("0", "↩ Назад", "")
        ]

        choice = menu(options, "СВОИ КАТЕГОРИИ")
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


# ── Единое меню категорий и направлений ──
def _menu_routing_rules(
    state: AppState,
    ps,
    destination_options: list[tuple[str, str]],
    ultimate_bundle: dict | None,
) -> None:
    list_targets = ps.config.setdefault("list_targets", {})
    local_lists = ps.config.setdefault("local_lists", {})
    from hydra.plugins.warp.plugin import EXTERNAL_LISTS

    while True:
        clear()
        categories = build_routing_catalog(EXTERNAL_LISTS, local_lists)
        destination_labels = dict(destination_options)
        destination_labels["none"] = "не настроено"
        destination_labels["mixed"] = "несколько направлений"
        lines = []
        for index, category in enumerate(categories, 1):
            target = category_target(category, list_targets)
            target_label = destination_labels.get(target, target)
            color = GREEN if target not in ("none", "mixed", "direct") else YELLOW if target == "direct" else DIM
            lines.append(f"  {index:<3} {category.label:<26} → {color}{target_label}{NC}")
        panel("🔀 КАТЕГОРИИ И НАПРАВЛЕНИЯ", lines or [f"  {DIM}Категории пока не найдены.{NC}"])
        options = [
            (str(index), category.label,
             f"{category.description} · {len(category.source_keys)} ист.")
            for index, category in enumerate(categories, 1)
        ]
        details_key = str(len(categories) + 1)
        options.append((details_key, "ℹ Что входит в категории", "Показать источники правил понятным списком"))
        options.append(("0", "↩ Назад", ""))
        choice = menu(options, "ВЫБЕРИТЕ КАТЕГОРИЮ — ЗАТЕМ КУДА ЕЁ НАПРАВИТЬ")
        if choice == "0":
            break
        if choice == details_key:
            detail_lines = []
            for category in categories:
                detail_lines.append(f"  {BOLD}{category.label}{NC} — {category.description}")
                detail_lines.extend(f"    • {source}" for source in category.sources)
            panel("СОСТАВ КАТЕГОРИЙ", detail_lines or ["  Нет источников правил."])
            prompt("Нажмите Enter для продолжения")
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(categories):
            continue
        category = categories[int(choice) - 1]
        chosen = _choose_destination(
            f"КУДА НАПРАВИТЬ: {category.label.upper()}", destination_options, ultimate_bundle
        )
        if chosen is None:
            continue
        previous_targets = {key: list_targets.get(key) for key in category.source_keys}
        for key in category.source_keys:
            list_targets[key] = chosen
        save_state(state)
        if any(key.startswith("ext:") for key in category.source_keys):
            info("Обновляю правила категории...")
            plugin = __import__("hydra.plugins.warp.plugin").plugins.warp.plugin.WarpPlugin()
            ok, message = plugin.update_external_rules()
            (success if ok else warn)(message)
        if ps.enabled:
            info("Применяю конфигурацию в Sing-Box...")
            if not orchestrator.apply_config(state):
                for key, previous in previous_targets.items():
                    if previous is None:
                        list_targets.pop(key, None)
                    else:
                        list_targets[key] = previous
                save_state(state)
                error("Ошибка применения конфигурации.")
                warn("Изменение маршрута отменено; предыдущая конфигурация сохранена.")
                last_error = _get_last_install_error()
                if last_error:
                    error(last_error[-1000:])
                prompt("Нажмите Enter для продолжения")
                continue
        if chosen == "none":
            success(f"Отдельный маршрут для «{category.label}» отключён.")
        else:
            success(f"«{category.label}» → {dict(destination_options).get(chosen, chosen)}")
        prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Управление профилями релеев ──
def _menu_geo_profiles(state: AppState, ps) -> None:
    from hydra.plugins.warp.plugin import WARP_PROFILES_DIR
    WARP_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    WARP_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        WARP_CONFIGS_DIR.chmod(0o700)
    except OSError:
        pass
    
    while True:
        clear()
        
        profiles = sorted([p.stem for p in WARP_PROFILES_DIR.glob("*.conf")])
        yaml_sources = discover_warp_yaml_sources()
        discovery_error = ""
        try:
            ultimate_bundle = load_or_refresh_warp_bundle()
        except ClashImportError as exc:
            ultimate_bundle = None
            discovery_error = str(exc)
        list_targets = ps.config.setdefault("list_targets", {})

        status_lines = [
            f"  {BOLD}Конфигурации:{NC} {WARP_CONFIGS_DIR}",
            f"  {BOLD}Одиночные профили:{NC} {WARP_PROFILES_DIR}",
            "  " + "─" * 60
        ]

        if ultimate_bundle:
            count = len(ultimate_bundle.get("endpoints", []))
            skipped = ultimate_bundle.get("skipped_unsupported", 0)
            endpoint_labels = dict(_ultimate_endpoint_options(ultimate_bundle))
            favourite_tags = ps.config.get("ultimate_route_tags", [])
            favourite_labels = [endpoint_labels[tag] for tag in favourite_tags if tag in endpoint_labels]
            status_lines.append(
                f"  {MAGENTA}Загружено:{NC} {ultimate_bundle.get('name', 'конфигурация')} — "
                f"{count} локаций" + (f", пропущено: {skipped}" if skipped else "")
            )
            selected_text = ", ".join(favourite_labels) if favourite_labels else "только прямое подключение и автовыбор"
            status_lines.append(f"  • Мои локации: {CYAN}{selected_text}{NC}")
            status_lines.append("  • Категории берутся из каталога HYDRA, а не из конфигурации")
            if count > 1:
                status_lines.append("  • Доступен автоматический выбор самой быстрой локации")
            status_lines.append("")
        elif discovery_error:
            status_lines.append(f"  {RED}Ошибка конфигурации:{NC} {discovery_error}")
            status_lines.append("")
        elif not yaml_sources:
            status_lines.append(f"  {DIM}Конфигурация не загружена. Выберите «Загрузить конфигурацию».{NC}")
            status_lines.append("")
        
        if not profiles and not ultimate_bundle and not discovery_error:
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
                
                routes_str = f"Категорий назначено: {len(mapped_lists)}" if mapped_lists else "Категории не назначены"
                
                status_lines.append(
                    f"  {idx}. {BOLD}{name:<17}{NC} [{type_str}]{warn_str} "
                    f"│ {DIM}{routes_str}{NC}"
                )
                
        panel("📍 ЛОКАЦИИ И КОНФИГУРАЦИЯ", status_lines)
        
        options = [("1", "📦 Загрузить конфигурацию", "Clash/Mihomo YAML с WARP-локациями и категориями")]
        if ultimate_bundle:
            options.append(("5", "📍 Выбрать используемые локации", "Они появятся в простом меню маршрутизации"))
            options.append(("2", "🗑️  Удалить конфигурацию", "Удалить импортированные локации и категории"))
        if profiles:
            options.append(("3", "🗑️  Удалить одиночный профиль", "Удалить .conf файл с диска"))
        options.append(("4", "💡 Показать инструкцию по установке", "Поддерживаемые форматы и установка"))
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ПРОФИЛИ РЕЛЕЕВ")
        if choice == "0":
            break
            
        elif choice == "1":
            if len(yaml_sources) > 1:
                error("Сначала оставьте в каталоге только один YAML-файл.")
                prompt("Нажмите Enter для продолжения")
                continue
            default_source = str(yaml_sources[0]) if len(yaml_sources) == 1 else str(WARP_ULTIMATE_SOURCE)
            source_raw = prompt("Путь к Clash/Mihomo YAML на сервере", default_source)
            if not source_raw.strip():
                continue
            if ultimate_bundle and not confirm("Заменить уже установленный Ultimate bundle?", default=False):
                continue
            previous_source = yaml_sources[0] if len(yaml_sources) == 1 else None
            try:
                bundle = import_clash_warp_bundle(Path(source_raw.strip()))
            except ClashImportError as exc:
                error(str(exc))
            else:
                imported_source = WARP_CONFIGS_DIR / Path(str(bundle["source_file"])).name
                if previous_source and previous_source != imported_source:
                    previous_source.unlink(missing_ok=True)
                valid_targets = {"warp_ultimate", "warp_ultimate_auto"}
                valid_targets.update(item["tag"] for item in bundle["endpoints"])
                for key, target in list(list_targets.items()):
                    if target.startswith("warp_ultimate_") and target not in valid_targets:
                        list_targets[key] = "none"
                    if key.startswith("yaml:"):
                        list_targets.pop(key, None)
                endpoint_tags = {item["tag"] for item in bundle["endpoints"]}
                if ps.config.get("ultimate_selected_tag") not in endpoint_tags:
                    ps.config["ultimate_selected_tag"] = bundle["endpoints"][0]["tag"]
                previous_favourites = [
                    tag for tag in ps.config.get("ultimate_route_tags", []) if tag in endpoint_tags
                ]
                ps.config["ultimate_route_tags"] = previous_favourites or [bundle["endpoints"][0]["tag"]]
                save_state(state)
                success(f"Импортировано WARP endpoints: {len(bundle['endpoints'])}.")
                skipped = bundle.get("skipped_unsupported", 0)
                if skipped:
                    warn(f"Пропущено неподдерживаемых Clash proxies: {skipped} (например, MASQUE).")
                for message in bundle.get("warnings", [])[:5]:
                    warn(message)
                if ps.enabled and not orchestrator.apply_config(state):
                    error("Bundle сохранён, но Sing-Box отклонил итоговый конфиг.")
                    _show_diagnostic_info()
                info("Теперь выберите локации, которые хотите видеть при маршрутизации.")
                _menu_route_locations(state, ps, bundle)
            prompt("Нажмите Enter для продолжения")

        elif choice == "2" and ultimate_bundle:
            if confirm("Удалить Ultimate bundle и отключить связанные маршруты?", default=False):
                source_name = str(ultimate_bundle.get("source_file", WARP_ULTIMATE_SOURCE.name))
                source_path = WARP_CONFIGS_DIR / Path(source_name).name
                WARP_ULTIMATE_BUNDLE.unlink(missing_ok=True)
                source_path.unlink(missing_ok=True)
                for key, target in list(list_targets.items()):
                    if target in ("warp_ultimate", "warp_ultimate_auto") or target.startswith("warp_ultimate_"):
                        list_targets[key] = "none"
                save_state(state)
                success("Ultimate bundle удалён.")
                if ps.enabled and not orchestrator.apply_config(state):
                    error("Не удалось применить конфигурацию после удаления.")
            prompt("Нажмите Enter для продолжения")

        elif choice == "3" and profiles:
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

        elif choice == "5" and ultimate_bundle:
            _menu_route_locations(state, ps, ultimate_bundle)
            success("Список локаций для маршрутизации сохранён.")
                    
        elif choice == "4":
            clear()
            lines = [
                f"  {BOLD}Конфигурация Clash/Mihomo:{NC}",
                "",
                f"  1. Скопируйте один .yaml/.yml в {WARP_CONFIGS_DIR}",
                "     Имя файла произвольное: HYDRA обнаружит его автоматически.",
                "  2. HYDRA извлечёт из файла только WARP-локации.",
                "  3. Отметьте локации, которые хотите использовать.",
                "  4. В «Категории и направления» выберите простой маршрут:",
                "     например, «Обход блокировок → Нидерланды».",
                "     Правила берутся из каталога HYDRA и своих списков.",
                "     rule-providers и rules из YAML намеренно игнорируются.",
                "     Clash TUN, DNS и listeners не импортируются.",
                "  5. Правила действуют на всех интерфейсах HYDRA.",
                "",
                f"  {BOLD}Одиночные .conf:{NC} по-прежнему поддерживаются в {WARP_PROFILES_DIR}.",
                "  MASQUE из Clash пока пропускается: его ключевой формат",
                "  несовместим с профилем MASQUE в sing-box-extended.",
            ]
            panel("ИНСТРУКЦИЯ ПО УСТАНОВКЕ", lines)
            prompt("Нажмите Enter, чтобы вернуться")
