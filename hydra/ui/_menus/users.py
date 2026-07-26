"""Compatibility facade for modular user and subscription menu controllers."""
from __future__ import annotations

import math
import re
import uuid as _uuid
from datetime import datetime

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.subscriptions.generator import get_subscription_urls
from hydra.services.user_access import (
    access_status as get_user_access_status,
    entitlement_status as get_user_entitlement_status,
)
from hydra.ui._menus.users_common import _application
from hydra.ui._menus.users_links import (
    _show_subscription_links,
    _user_configs,
    _user_links,
)
from hydra.ui._menus.users_management import (
    _reconcile_user_access,
    _toggle_block,
    _user_detail_menu,
    menu_users,
)
from hydra.ui._menus.users_overview import (
    _add_user,
    _select_user,
    _show_user_detail,
    _show_users,
)
from hydra.ui._menus.users_subscription import (
    _obtain_cert_for_sub,
    install_sub_systemd_service,
    menu_subscription_server,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bar,
    _bytes_auto,
    clear,
    confirm,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    title,
    warn,
)


__all__ = [
    "_add_user",
    "_application",
    "_obtain_cert_for_sub",
    "_reconcile_user_access",
    "_select_user",
    "_show_subscription_links",
    "_show_user_detail",
    "_show_users",
    "_toggle_block",
    "_user_configs",
    "_user_detail_menu",
    "_user_links",
    "install_sub_systemd_service",
    "menu_subscription_server",
    "menu_users",
]
