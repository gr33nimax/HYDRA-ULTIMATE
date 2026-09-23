"""External-source and route interactions for the WARP manager facade."""

from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BOLD,
    CYAN,
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

_SOURCE_PAGE_SIZE = 20


def _list_targets(ps) -> dict:
    targets = ps.config.get("list_targets")
    if not isinstance(targets, dict):
        targets = {}
        ps.config["list_targets"] = targets
    return targets


def _local_lists(ps) -> dict:
    lists = ps.config.get("local_lists")
    if not isinstance(lists, dict):
        lists = {}
        ps.config["local_lists"] = lists
    return lists


def _destinations(app: ApplicationService) -> list[str]:
    observation = facade._warp_observation(app)
    destinations = ["direct", "warp"]
    for name in sorted(
        str(row["name"]) for row in observation.get("profiles", []) if isinstance(row, dict) and row.get("name")
    ):
        destinations.append(f"warp_{name}")
    return destinations


def _choose_target(destinations: list[str], title: str) -> str | None:
    """Return the chosen destination, ``none`` to detach, or None to cancel."""
    options = [
        (str(index), destination, f"Направить на {destination}")
        for index, destination in enumerate(destinations, start=1)
    ]
    options.append(
        (
            str(len(destinations) + 1),
            "none (отключить)",
            "Снять маршрут со списка",
        ),
    )
    options.append(("0", "Отмена", ""))
    index = facade._menu_number(menu(options, title))
    if index is None:
        return None
    if 1 <= index <= len(destinations):
        return destinations[index - 1]
    if index == len(destinations) + 1:
        return "none"
    return None


def _apply_target(
    state: AppState,
    ps,
    app: ApplicationService,
    keys: list[str],
    target: str,
    label: str,
) -> None:
    """Commit one destination for every key and report what happened."""
    if target != "none" and any(key.startswith("ext:") for key in keys):
        info("Скачиваю списки правил...")
    if ps.enabled:
        info("Применяю конфигурацию в Sing-Box...")
    ok, message = facade._commit_route_targets(state, ps, keys, target, app)
    if ok:
        success(
            f"{label}: маршрут снят." if target == "none" else f"{label} направлен на {target}!",
        )
    else:
        error(message)
        if ps.enabled:
            facade._show_diagnostic_info(app)


def _counts(category: dict) -> tuple[int, int]:
    """Sources carrying a route in this category, and how many it has."""
    total = category.get("total")
    routed = category.get("routed")
    return (
        routed if isinstance(routed, int) else 0,
        total if isinstance(total, int) else len(category.get("source_keys") or ()),
    )


def _target_label(target: str, routed: int = 1, total: int = 1) -> str:
    """Render one destination, naming the sources it actually covers."""
    if routed == 0 or target == "none":
        return f"{RED}выключено{NC}"
    if target == "mixed":
        body = f"{YELLOW}разные направления{NC}"
    else:
        body = f"{GREEN if target != 'direct' else YELLOW}{target}{NC}"
    if routed < total:
        return f"{body} {DIM}({routed} из {total}){NC}"
    return body


def _category_lines(categories: list[dict]) -> list[str]:
    enabled = sum(1 for category in categories if category.get("routed"))
    return [
        f"  {BOLD}Каталог Geo-Aggregator:{NC} {len(categories)} категорий, включено {enabled}.",
        "  " + "─" * 60,
        "  Категория направляется целиком; внутри — конкретные сервисы",
        "  (youtube, google, telegram), и каждый можно направить отдельно.",
        f"  {DIM}«обычно → WARP» — сервису нужен иностранный адрес, «обычно → DIRECT» — российский.{NC}",
    ]


def _category_row(category: dict) -> str:
    """One menu row: what the category is, where it goes, where it usually goes."""
    target = _target_label(str(category["target"]), *_counts(category))
    direction = str(category.get("direction") or "")
    row = f"{category['label']} — {target}"
    return f"{row} {DIM}· {direction.upper()}{NC}" if direction else row


def _menu_category_sources(
    state: AppState,
    ps,
    app: ApplicationService,
    category: dict,
) -> None:
    keys = [str(key) for key in category["source_keys"]]
    while True:
        clear()
        list_targets = _list_targets(ps)
        note = str(category.get("note") or "")
        panel(
            f"🔗 {str(category['label']).upper()}",
            [
                f"  {category['description']}",
                f"  Сервисов в категории: {len(keys)}",
                f"  Сейчас: {_target_label(str(category['target']), *_counts(category))}",
                "  " + "─" * 55,
                *([f"  {note}", "  " + "─" * 55] if note else []),
                "  Категория направляется целиком, но отдельный сервис",
                "  можно переопределить внутри неё.",
            ],
            wrap=True,
        )
        options = [
            (
                "1",
                "🎯 Направить всю категорию",
                "Один маршрут для всех списков категории",
            ),
            (
                "2",
                f"📋 Сервисы внутри ({len(keys)})",
                "Поиск по названию и отдельный маршрут каждому сервису",
            ),
            ("0", "↩ Назад", ""),
        ]
        choice = menu(options, str(category["label"]))
        if choice == "0":
            return
        if choice == "1":
            title = f"МАРШРУТ ДЛЯ {str(category['label']).upper()}"
            target = _choose_target(_destinations(app), title)
            if target is not None:
                _apply_target(
                    state,
                    ps,
                    app,
                    keys,
                    target,
                    str(category["label"]),
                )
                prompt("Нажмите Enter для продолжения")
        elif choice == "2":
            _menu_category_source_list(state, ps, app, category)


def _filter_sources(sources: list[tuple[str, str]], query: str) -> list[tuple[str, str]]:
    """Sources whose name or key contains the query, in catalogue order."""
    needle = query.strip().lower()
    if not needle:
        return sources
    return [
        item
        for item in sources
        if needle in str(item[1]).lower() or needle in str(item[0]).lower()
    ]


def _menu_category_source_list(
    state: AppState,
    ps,
    app: ApplicationService,
    category: dict,
) -> None:
    all_sources = list(zip(category["source_keys"], category["sources"]))
    query = ""
    page = 0
    while True:
        clear()
        list_targets = _list_targets(ps)
        sources = _filter_sources(all_sources, query)
        total_pages = max(
            1,
            (len(sources) + _SOURCE_PAGE_SIZE - 1) // _SOURCE_PAGE_SIZE,
        )
        page = min(page, total_pages - 1)
        start = page * _SOURCE_PAGE_SIZE
        chunk = sources[start : start + _SOURCE_PAGE_SIZE]
        found = (
            f"Поиск «{query}»: найдено {len(sources)} из {len(all_sources)}"
            if query
            else f"Всего сервисов: {len(sources)}"
        )
        lines = [
            f"  {found}",
            f"  Страница {page + 1} из {total_pages} "
            f"(показано {start + 1}-{start + len(chunk)})",
            "  " + "─" * 55,
        ]
        if not chunk:
            lines.append(f"  {DIM}Ничего не найдено.{NC}")
        for offset, (key, name) in enumerate(chunk, start=start + 1):
            target = str(list_targets.get(key) or "none")
            lines.append(
                f"  {offset:>3}. {CYAN}{str(name):<30}{NC} {_target_label(target)}",
            )
        lines.extend(
            [
                "  " + "─" * 55,
                "  Ввод: номер — задать маршрут, текст — поиск (например youtube),",
                "  [n]/[p] — страницы, [-] — сбросить поиск, [0] — назад",
            ]
        )
        panel(f"🔗 {str(category['label']).upper()} · СЕРВИСЫ", lines)

        raw = prompt("Выбор").strip()
        if raw == "0":
            return
        if raw.lower() == "n":
            page = min(page + 1, total_pages - 1)
            continue
        if raw.lower() == "p":
            page = max(page - 1, 0)
            continue
        if raw == "-":
            query = ""
            page = 0
            continue
        index = facade._menu_number(raw)
        if index is not None:
            if not start + 1 <= index <= start + len(chunk):
                continue
            key, name = sources[index - 1]
            target = _choose_target(
                _destinations(app),
                f"МАРШРУТ ДЛЯ {str(name).upper()}",
            )
            if target is None:
                continue
            _apply_target(state, ps, app, [key], target, str(name))
            prompt("Нажмите Enter для продолжения")
            continue
        query = raw
        page = 0


def _menu_external_sources_toggle(
    state: AppState,
    ps,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        categories = facade._warp_catalog(
            app,
            list_targets=_list_targets(ps),
            local_lists=_local_lists(ps),
        )
        if not categories:
            warn("Каталог списков пуст — источник недоступен.")
            prompt("Нажмите Enter для продолжения")
            return
        panel("🔗 СПИСКИ ПРАВИЛ (Geo-Aggregator)", _category_lines(categories))
        options = [
            (
                str(index),
                _category_row(category),
                str(category["description"]),
            )
            for index, category in enumerate(categories, start=1)
        ]
        options.append(("0", "↩ Назад", ""))
        choice = menu(options, "КАТЕГОРИИ СПИСКОВ")
        if choice == "0":
            return
        index = facade._menu_number(choice)
        if index is None or not 1 <= index <= len(categories):
            continue
        _menu_category_sources(state, ps, app, categories[index - 1])


# ── Вспомогательное меню: Настройка маршрутизации списков ──
def _menu_routing_rules(
    state: AppState,
    ps,
    destinations: list[str],
    app: ApplicationService,
) -> None:
    while True:
        clear()
        list_targets = _list_targets(ps)
        local_lists = _local_lists(ps)
        external_sources = facade._external_sources(app)

        status_lines = [f"  {BOLD}Текущее сопоставление списков и точек выхода:{NC}", "  " + "─" * 60]

        active_rules = []

        # 1. Локальные списки
        for name in local_lists.keys():
            key = f"local:{name}"
            target = str(list_targets.get(key) or "none")
            active_rules.append((key, name + " (локал.)", target))

        # 2. Внешние списки: только включённые, иначе каталог не помещается
        for name, item in external_sources.items():
            key = f"ext:{name}"
            target = str(list_targets.get(key) or "none")
            if target == "none":
                continue
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

        index = facade._menu_number(choice)
        if index is None or not 1 <= index <= len(active_rules):
            continue
        key, display_name, _current = active_rules[index - 1]
        target = _choose_target(
            destinations,
            f"НАПРАВЛЕНИЕ ДЛЯ {display_name.upper()}",
        )
        if target is None:
            continue

        if key.startswith("ext:") and target != "none":
            info("Скачиваю список правил...")
        if ps.enabled:
            info("Применяю конфигурацию в Sing-Box...")
        ok, msg = facade._commit_route_target(
            state,
            ps,
            key,
            target,
            app,
        )
        if ok:
            success(
                f"Маршрут для {display_name} отключен."
                if target == "none"
                else f"Маршрут для {display_name} изменен на {target} и применён!",
            )
        else:
            error(msg)
            if ps.enabled:
                facade._show_diagnostic_info(app)
        prompt("Нажмите Enter для продолжения")
