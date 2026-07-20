"""TUI manager for Anti-DPI state and evidence."""
from __future__ import annotations

import ipaddress

import hydra.core.orchestrator as orchestrator
from hydra.core.state import AppState
from hydra.ui.tui import clear, menu, panel, prompt, success, warn


def menu_antidpi(state: AppState, plugin) -> None:
    while True:
        status = plugin.status()
        data = plugin._load_state()
        banned = data.get("banned", {})
        whitelist = data.get("whitelist", [])
        clear()
        panel("ANTI-DPI", [
            f"  Служба: {'активна' if status.running else 'остановлена'}",
            f"  Событий: {data.get('events', 0)}",
            f"  Заблокировано: {len(banned)}",
            f"  Whitelist: {len(whitelist)}",
        ])
        choice = menu([
            ("1", "Остановить" if status.running else "Запустить", "Управление детектором"),
            ("2", "Заблокированные адреса", "Evidence и score"),
            ("3", "Добавить whitelist", "IP или CIDR"),
            ("4", "Очистить истёкшие записи", "Синхронизация persistent state"),
            ("0", "Назад", ""),
        ], "ANTI-DPI")
        if choice == "0":
            return
        if choice == "1":
            ok = orchestrator.disable(state, "antidpi") if status.running else orchestrator.enable(state, "antidpi")
            success("Состояние изменено") if ok else warn("Не удалось изменить состояние")
            prompt("Enter")
        elif choice == "2":
            lines = [f"  {ip}: score={meta.get('score', 0)} signals={','.join(meta.get('signals', []))}" for ip, meta in banned.items()]
            panel("ЗАБЛОКИРОВАННЫЕ", lines or ["  Список пуст"])
            prompt("Enter")
        elif choice == "3":
            raw = prompt("IP/CIDR").strip()
            try:
                network = str(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                warn("Некорректный IP/CIDR")
            else:
                if network not in whitelist:
                    whitelist.append(network)
                    data["whitelist"] = whitelist
                    plugin._save_state(data)
                    success("Добавлено")
            prompt("Enter")
        elif choice == "4":
            plugin._restore_bans()
            success("Состояние синхронизировано")
            prompt("Enter")
