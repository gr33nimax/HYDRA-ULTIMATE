"""Informative TUI manager for the Anti-DPI detector."""
from __future__ import annotations

import ipaddress

import hydra.core.orchestrator as orchestrator
from hydra.core.host import HOST
from hydra.core.state import AppState
from hydra.ui.tui import CYAN, DIM, GREEN, RED, clear, menu, panel, prompt, success, warn


def menu_antidpi(state: AppState, plugin) -> None:
    while True:
        status = plugin.status()
        data = plugin._load_state()
        banned = data.get("banned", {})
        whitelist = data.get("whitelist", [])
        health = plugin.health_result()
        clear()
        panel("ANTI-DPI", [
            f"  Служба: {GREEN if status.running else RED}{'ACTIVE' if status.running else 'STOPPED'}{DIM}   health={'OK' if health.healthy else 'FAIL'}",
            f"  События: {data.get('events', 0)}   Бан: {len(banned)}   Whitelist: {len(whitelist)}",
            f"  Backend: {GREEN if health.checks.get('ipsets') else RED}{'ipset OK' if health.checks.get('ipsets') else 'ipset FAIL'}{DIM}   "
            f"Firewall: {GREEN if health.checks.get('firewall') else RED}{'OK' if health.checks.get('firewall') else 'FAIL'}{DIM}",
            f"  Последняя ошибка: {status.info.get('last_error') or 'нет'}",
        ])
        choice = menu([
            ("1", "Остановить" if status.running else "Запустить", "Управление detector service"),
            ("2", "Заблокированные IP", "Evidence, score, signals и время бана"),
            ("3", "Добавить whitelist", "IP или CIDR без ложных банов"),
            ("4", "Синхронизировать bans", "Восстановить ipset и удалить истёкшие записи"),
            ("5", "Диагностика", "Команды, health checks и journalctl"),
            ("6", "Снять бан", "Удалить IP из ipset и evidence"),
            ("7", "Сбросить evidence", "Удалить score без изменения whitelist"),
            ("0", "Назад", ""),
        ], "ANTI-DPI")
        if choice == "0":
            return
        if choice == "1":
            try:
                ok = orchestrator.disable(state, "antidpi") if status.running else orchestrator.enable(state, "antidpi")
                success("Состояние изменено") if ok else warn("Не удалось изменить состояние")
            except Exception as exc:
                warn(str(exc))
            prompt("Enter")
        elif choice == "2":
            lines = [
                f"  {CYAN}{ip}{DIM} score={meta.get('score', 0)} signals={','.join(meta.get('signals', []))} at={meta.get('at', '?')}"
                for ip, meta in banned.items()
            ]
            panel("ЗАБЛОКИРОВАННЫЕ IP", lines or ["  Список пуст"])
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
            success("Состояние синхронизировано") if plugin._restore_bans() else warn("Не удалось синхронизировать bans")
            prompt("Enter")
        elif choice == "5":
            deps = [
                f"  {GREEN if HOST.which(command) else RED}{command}: {'OK' if HOST.which(command) else 'MISSING'}"
                for command in plugin.meta.required_commands
            ]
            lines = deps + [f"  health: {'OK' if health.healthy else 'FAIL'}", "  journalctl -u hydra-antidpi -n 80 --no-pager"]
            if health.detail:
                lines.append(f"  detail: {health.detail}")
            panel("DIAGNOSTICS", lines)
            prompt("Enter")
        elif choice == "6":
            raw = prompt("IP для разбана").strip()
            success("Бан снят") if plugin.unban(raw) else warn("Не удалось снять бан")
            prompt("Enter")
        elif choice == "7":
            raw = prompt("IP для сброса evidence").strip()
            try:
                address = ipaddress.ip_address(raw).compressed
                data.get("scores", {}).pop(address, None)
                plugin._save_state(data)
                success("Evidence сброшен")
            except ValueError:
                warn("Некорректный IP")
            prompt("Enter")
