"""External-source and route interactions for the WARP manager facade."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BOLD,
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
    warn,
)

def _menu_external_sources_toggle(
    state: AppState,
    ps,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        list_targets = ps.config.setdefault("list_targets", {})
        external_sources = facade._external_sources(app)

        status_lines = []
        for key, item in external_sources.items():
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
        for idx, (key, item) in enumerate(external_sources.items(), start=1):
            target = list_targets.get(f"ext:{key}", "none")
            action = "Отключить" if target != "none" else "Включить"
            opts.append((str(idx), f"Toggle {item['name']}", f"{action} {item['name']}"))

        opts.append(("0", "↩ Назад", ""))

        choice = menu(opts, "ВНЕШНИЕ ИСТОЧНИКИ")
        if choice == "0":
            break

        elif choice.isdigit() and 1 <= int(choice) <= len(external_sources):
            keys = list(external_sources.keys())
            key = keys[int(choice) - 1]
            target = list_targets.get(f"ext:{key}", "none")

            if target != "none":
                list_targets[f"ext:{key}"] = "none"
                app.admin.save_state(state)
                success(f"Список {external_sources[key]['name']} успешно отключен.")
                if ps.enabled:
                    app.apply(state)
            else:
                success(f"Включаем список {external_sources[key]['name']}.")
                observation = facade._warp_observation(app)
                destinations = ["direct"]
                custom_profiles = sorted(
                    str(row["name"])
                    for row in observation.get("profiles", [])
                    if isinstance(row, dict) and row.get("name")
                )
                for p in custom_profiles:
                    destinations.append(f"warp_{p}")
                if observation.get("default_profile_exists"):
                    destinations.append("warp")

                opts_dest = []
                for i, d in enumerate(destinations, start=1):
                    opts_dest.append((str(i), d, f"Направить трафик на {d}"))

                d_choice = menu(opts_dest, f"ВЫБЕРИТЕ НАПРАВЛЕНИЕ ДЛЯ {external_sources[key]['name'].upper()}")
                if d_choice.isdigit():
                    d_idx = int(d_choice) - 1
                    if 0 <= d_idx < len(destinations):
                        chosen_dest = destinations[d_idx]
                        list_targets[f"ext:{key}"] = chosen_dest
                        app.admin.save_state(state)
                        success(f"Список {external_sources[key]['name']} направлен на {chosen_dest}!")

                        info("Скачиваю список правил...")
                        ok, msg = app.plugin_action(
                            "warp",
                            "update_external_rules",
                            state=state,
                        )
                        if ok:
                            success(msg)
                        else:
                            warn(msg)

                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                            app.apply(state)

            prompt("Нажмите Enter для продолжения")


# ── Вспомогательное меню: Настройка маршрутизации списков ──
def _menu_routing_rules(
    state: AppState,
    ps,
    destinations: list[str],
    app: ApplicationService,
) -> None:
    while True:
        clear()
        list_targets = ps.config.setdefault("list_targets", {})
        local_lists = ps.config.setdefault("local_lists", {})
        external_sources = facade._external_sources(app)

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
        for name, item in external_sources.items():
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
                        if key.startswith("ext:") and chosen_dest != "none":
                            info("Скачиваю список правил...")
                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                        ok, msg = facade._commit_route_target(
                            state,
                            ps,
                            key,
                            chosen_dest,
                            app,
                        )
                        if ok:
                            success(f"Маршрут для {display_name} изменен на {chosen_dest} и применён!")
                        else:
                            error(msg)
                            if ps.enabled:
                                facade._show_diagnostic_info(app)
                    elif d_idx == len(destinations):
                        if ps.enabled:
                            info("Применяю конфигурацию в Sing-Box...")
                        ok, msg = facade._commit_route_target(
                            state,
                            ps,
                            key,
                            "none",
                            app,
                        )
                        if ok:
                            success(f"Маршрут для {display_name} отключен.")
                        else:
                            error(msg)
                            if ps.enabled:
                                facade._show_diagnostic_info(app)

                prompt("Нажмите Enter для продолжения")
