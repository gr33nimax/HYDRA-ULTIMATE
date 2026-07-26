"""
hydra/plugins/warp/manager.py — TUI-консоль управления Cloudflare WARP.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import bind_facade
from hydra.ui.tui import (
    BOLD,
    DIM,
    NC,
    RED,
    YELLOW,
    warn,
)


def _implementation_scope():
    return bind_facade(sys.modules[__name__])


def _warp_observation(app: ApplicationService) -> dict[str, object]:
    return app.plugin_query("warp", "manager_observation")


def _external_sources(app: ApplicationService) -> dict[str, dict[str, str]]:
    return app.plugin_query("warp", "external_sources")


def _get_last_install_error(app: ApplicationService) -> str:
    result = app.logs.read("file", "/var/log/hydra/install.log", 200)
    for line in reversed(result.lines):
        upper = line.upper()
        if (
            "[ERROR]" in upper
            or "CONFIG INVALID" in upper
            or "FAILED" in upper
        ):
            return line
    return ""


def _show_diagnostic_info(app: ApplicationService) -> None:
    print(f"\n  {YELLOW}═══════════════ ДИАГНОСТИКА ОШИБКИ ═══════════════{NC}")

    install_err = _get_last_install_error(app)
    if install_err:
        warn("Последняя ошибка из /var/log/hydra/install.log:")
        print(f"  {RED}{install_err}{NC}")

    debug_path = "/var/log/hydra/warp_debug_config.json"
    if app.diagnostics.path_exists(debug_path):
        warn("Секции outbounds и route из сгенерированного конфига:")
        try:
            cfg = app.diagnostics.read_json_file(debug_path)
            print(f"  {BOLD}outbounds:{NC}")
            print(f"  {DIM}{json.dumps(cfg.get('outbounds', []), indent=2)}{NC}")
            print(f"  {BOLD}route:{NC}")
            print(f"  {DIM}{json.dumps(cfg.get('route', {}), indent=2)}{NC}")
        except Exception as e:
            print(f"  Ошибка чтения конфига: {e}")

    r = app.admin.run_command(
        ["systemctl", "status", "sing-box"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        warn("Служба sing-box неактивна или сообщает об ошибке.")

    r2 = app.admin.run_command(
        ["journalctl", "-u", "sing-box", "-n", "10", "--no-pager"],
        capture_output=True,
        text=True,
    )
    if r2.stdout:
        warn("Последние 10 строк логов sing-box из journalctl:")
        for line in r2.stdout.splitlines():
            print(f"  {DIM}{line}{NC}")

    print(f"  {YELLOW}══════════════════════════════════════════════════{NC}\n")


def _restore_route_target(list_targets: dict, key: str, existed: bool, value: str | None) -> None:
    if existed:
        list_targets[key] = value
    else:
        list_targets.pop(key, None)


def _valid_domain(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        ),
    )


def _valid_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _commit_route_target(
    state: AppState,
    ps,
    key: str,
    target: str,
    app: ApplicationService,
) -> tuple[bool, str]:
    """Persist and apply a mapping, restoring desired state if it is rejected."""
    list_targets = ps.config.setdefault("list_targets", {})
    existed = key in list_targets
    previous = list_targets.get(key)
    list_targets[key] = target
    app.admin.save_state(state)

    if key.startswith("ext:") and target != "none":
        ok, message = app.plugin_action(
            "warp",
            "update_external_rules",
            state=state,
        )
        if not ok:
            _restore_route_target(list_targets, key, existed, previous)
            app.admin.save_state(state)
            return False, message

    if ps.enabled and not app.apply(state):
        apply_error = app.apply_error() or "неизвестная ошибка применения"
        _restore_route_target(list_targets, key, existed, previous)
        state.protocols["warp"] = ps
        app.admin.save_state(state)
        return False, f"Sing-Box отклонил маршрут; изменение отменено: {apply_error}"

    return True, ""


def menu_warp(
    state: AppState,
    app: ApplicationService,
) -> None:
    """Run the specialised controller through the stable manager facade."""
    from hydra.ui.plugin_managers._warp_menu import run

    with _implementation_scope():
        run(state, app)


def _menu_rules_lists(
    state: AppState,
    plugin_state,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._warp_local_lists import (
        _menu_rules_lists as run,
    )

    with _implementation_scope():
        run(state, plugin_state, app)


def _menu_manage_local_list_items(
    state: AppState,
    plugin_state,
    name: str,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._warp_local_lists import (
        _menu_manage_local_list_items as run,
    )

    with _implementation_scope():
        run(state, plugin_state, name, app)


def _menu_external_sources_toggle(
    state: AppState,
    plugin_state,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._warp_routing import (
        _menu_external_sources_toggle as run,
    )

    with _implementation_scope():
        run(state, plugin_state, app)


def _menu_routing_rules(
    state: AppState,
    plugin_state,
    destinations: list[str],
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._warp_routing import (
        _menu_routing_rules as run,
    )

    with _implementation_scope():
        run(state, plugin_state, destinations, app)


def _menu_geo_profiles(
    state: AppState,
    plugin_state,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._warp_profiles import (
        _menu_geo_profiles as run,
    )

    with _implementation_scope():
        run(state, plugin_state, app)
