"""Architecture contract for the decomposed Telegram admin adapter."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from hydra.services.telegram import dashboards, security_actions
from hydra.services.telegram.controller import AdminBot


TELEGRAM_ROOT = Path(__file__).parents[1] / "hydra" / "services" / "telegram"
FACADES = {
    "controller.py",
    "dashboards.py",
    "security_actions.py",
}
COMPANIONS = {
    "controller_callbacks.py",
    "controller_runtime.py",
    "controller_views.py",
    "dashboard_antidpi.py",
    "dashboard_common.py",
    "dashboard_fail2ban.py",
    "dashboard_honeypot.py",
    "dashboard_system.py",
    "security_ip_actions.py",
    "security_keyboards.py",
    "security_monitors.py",
    "security_settings.py",
}


def _tree(filename: str) -> ast.Module:
    return ast.parse(
        (TELEGRAM_ROOT / filename).read_text(encoding="utf-8"),
    )


def _local_imports(filename: str) -> set[str]:
    result = set()
    for node in ast.walk(_tree(filename)):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module == "hydra.services.telegram":
            result.update(alias.name for alias in node.names)
        elif (
            node.module
            and node.module.startswith("hydra.services.telegram.")
        ):
            result.add(node.module.rsplit(".", 1)[-1])
    return result


def test_telegram_admin_modules_and_functions_stay_bounded() -> None:
    for filename in FACADES | COMPANIONS:
        source = (TELEGRAM_ROOT / filename).read_text(encoding="utf-8")
        limit = 200 if filename in FACADES else 350
        assert len(source.splitlines()) <= limit, filename
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                size = node.end_lineno - node.lineno + 1
                assert size <= 100, f"{filename}:{node.name} ({size})"


def test_dashboard_and_security_domains_do_not_import_facades_backwards() -> None:
    for filename in COMPANIONS:
        if filename.startswith("dashboard_"):
            assert "dashboards" not in _local_imports(filename), filename
        if filename.startswith("security_"):
            assert "security_actions" not in _local_imports(filename), filename
        assert "controller" not in _local_imports(filename), filename


def test_telegram_admin_companion_graph_is_acyclic() -> None:
    graph = {
        filename.removesuffix(".py"): {
            target
            for target in _local_imports(filename)
            if f"{target}.py" in COMPANIONS
        }
        for filename in COMPANIONS
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise AssertionError(f"Telegram admin cycle through {node}")
        if node in visited:
            return
        visiting.add(node)
        for target in graph.get(node, set()):
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def test_dashboard_facade_keeps_historical_symbol_surface() -> None:
    expected = {
        "_format_period",
        "_format_security_timestamp",
        "_legacy_fail2ban_dashboard_text",
        "_legacy_honeypot_status_text",
        "_lookup_security_intel",
        "_network_label",
        "_parse_fail2ban_ban_lines",
        "_parse_fail2ban_jail",
        "get_antidpi_dashboard_text",
        "get_antidpi_status_text",
        "get_fail2ban_dashboard_text",
        "get_fail2ban_status_text",
        "get_honeypot_status_text",
        "get_system_info_text",
    }
    assert set(dashboards.__all__) == expected
    assert all(callable(getattr(dashboards, name)) for name in expected)


def test_dashboard_facade_keeps_historical_signatures() -> None:
    expected = {
        "_format_period": ["seconds"],
        "_format_security_timestamp": ["value"],
        "_legacy_fail2ban_dashboard_text": ["app"],
        "_legacy_honeypot_status_text": ["app"],
        "_lookup_security_intel": ["addresses"],
        "_network_label": ["intel"],
        "_parse_fail2ban_ban_lines": ["lines", "limit"],
        "_parse_fail2ban_jail": ["detail"],
        "_recent_fail2ban_bans": ["app", "limit"],
        "get_antidpi_dashboard_text": ["app"],
        "get_antidpi_status_text": ["app"],
        "get_fail2ban_dashboard_text": ["app"],
        "get_fail2ban_status_text": ["app"],
        "get_honeypot_status_text": ["app"],
        "get_system_info_text": ["app"],
    }
    for name, parameters in expected.items():
        assert list(inspect.signature(getattr(dashboards, name)).parameters) == (
            parameters
        )


def test_security_facade_keeps_historical_symbol_surface() -> None:
    expected = {
        "_antidpi_keyboard",
        "_back_keyboard",
        "_fail2ban_keyboard",
        "_fail2ban_monitor_worker",
        "_honeypot_keyboard",
        "_honeypot_monitor_worker",
        "_main_keyboard",
        "_notification_keyboard",
        "_notification_settings_text",
        "_process_fail2ban_log_line",
        "_process_honeypot_log_line",
        "_set_plugin_running",
        "_toggle_antidpi",
        "_toggle_fail2ban",
        "_toggle_honeypot",
        "_toggle_notification",
        "ban_ip_antidpi",
        "unban_ip_everywhere",
    }
    assert set(security_actions.__all__) == expected
    assert all(callable(getattr(security_actions, name)) for name in expected)


def test_security_facade_keeps_historical_signatures() -> None:
    expected = {
        "_antidpi_keyboard": ["app"],
        "_back_keyboard": ["refresh", "extra"],
        "_fail2ban_keyboard": ["app"],
        "_fail2ban_monitor_worker": ["stop_event", "app", "notify"],
        "_follow_plugin_log": ["stop_event", "fetch", "process"],
        "_honeypot_keyboard": ["app"],
        "_honeypot_monitor_worker": ["stop_event", "app", "notify"],
        "_main_keyboard": [],
        "_notification_keyboard": [],
        "_notification_settings_text": [],
        "_process_fail2ban_log_line": ["line", "notify"],
        "_process_honeypot_log_line": ["line", "app", "notify"],
        "_set_plugin_running": ["state", "name", "running", "app"],
        "_toggle_antidpi": ["app"],
        "_toggle_fail2ban": ["app"],
        "_toggle_honeypot": ["app"],
        "_toggle_notification": ["field"],
        "ban_ip_antidpi": ["ip", "app"],
        "unban_ip_everywhere": ["ip", "app"],
    }
    for name, parameters in expected.items():
        assert list(
            inspect.signature(getattr(security_actions, name)).parameters,
        ) == parameters


def test_admin_bot_keeps_constructor_and_handler_signatures() -> None:
    assert list(inspect.signature(AdminBot).parameters) == [
        "token",
        "admin_chat_id",
        "application",
        "notifier",
    ]
    expected = {
        "_check_admin": ["self", "update"],
        "_show": ["self", "update", "text", "keyboard"],
        "cmd_start": ["self", "update", "context"],
        "cmd_system": ["self", "update", "context"],
        "cmd_antidpi": ["self", "update", "context"],
        "cmd_honeypot": ["self", "update", "context"],
        "cmd_fail2ban": ["self", "update", "context"],
        "cmd_notifications": ["self", "update", "context"],
        "cmd_unban": ["self", "update", "context"],
        "handle_message": ["self", "update", "context"],
        "handle_callback": ["self", "update", "context"],
        "run": ["self"],
    }
    for name, parameters in expected.items():
        assert list(inspect.signature(getattr(AdminBot, name)).parameters) == (
            parameters
        )
