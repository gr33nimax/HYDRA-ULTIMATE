"""Calls cookies for one node: an explicitly chosen file, imported over pinned SSH.

Cookies are per-node material: the base's own cookies are never copied, no calls are
created by importing them, and the managed pool is not recreated. The operator picks
the file for this node, and the import needs an explicit confirmation.
"""

from __future__ import annotations

from hydra.core.state_nodes import NodeConfig
from hydra.services.application import ApplicationService
from hydra.ui.tui import ask, confirm, error, kv, panel, success


def calls_use_cookies(node: NodeConfig) -> bool:
    calls = node.protocols.get("calls")
    return calls is not None and calls.enabled


def calls_cookies_prompt(node: NodeConfig, app: ApplicationService) -> bool:
    """Offer the cookie import only where it is meaningful, and only on request."""
    if not calls_use_cookies(node):
        return False
    if not confirm("Импортировать отдельные VK cookies для этой ноды?", default=False):
        return False
    import_vk_cookies(node, app)
    return True


def import_vk_cookies(node: NodeConfig, app: ApplicationService) -> None:
    panel(
        "VK COOKIES НОДЫ",
        [
            kv("Нода:", node.label),
            "Выбери отдельный JSON-файл; cookies основы автоматически не копируются.",
            "Импорт по pinned SSH заменяет cookies только на этой ноде.",
            "Звонки не создаются и существующий пул не пересоздаётся.",
            "WhitelistBypass.Creator: github.com/kulikov0/whitelist-bypass/releases",
        ],
        wrap=True,
    )
    source = ask("Путь к отдельному VK cookies JSON (0 — отмена)")
    if source in (None, "0"):
        return
    if confirm("Передать cookies только этой ноде?", default=False):
        try:
            app.nodes.import_vk_cookies(node.id, source)
        except Exception as exc:
            error(f"Cookies не импортированы: {exc if str(exc) else type(exc).__name__}")
            return
        success("Cookies импортированы на ноду; пул звонков не изменён")


__all__ = ["calls_cookies_prompt", "calls_use_cookies", "import_vk_cookies"]
