"""hydra/core/orchestrator.py — единая точка применения конфигурации."""
from __future__ import annotations

from hydra.core.state import AppState, User, save_state, get_protocol, find_user
from hydra.core import singbox, nft
from hydra.plugins import registry


def apply_config(state: AppState) -> bool:
    fragments = registry.collect_fragments(state)
    cfg = singbox.generate_config(state, fragments)
    if not singbox.write_config(cfg):
        return False
    try:
        if state.network.tproxy_enabled:
            nft.apply_tproxy(fragments, state.network.tproxy_port)
        else:
            nft.clear_tproxy()
    except Exception:
        pass
    return singbox.reload()


def install_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    ok = p.install()
    proto = get_protocol(state, name)
    proto.installed = ok
    save_state(state)
    return ok


def uninstall_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    ok = p.uninstall()
    proto = get_protocol(state, name)
    proto.installed = False
    proto.enabled = False
    save_state(state)
    apply_config(state)
    return ok


def enable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    p.on_enable(state)
    proto = get_protocol(state, name)
    proto.enabled = True
    save_state(state)
    return apply_config(state)


def disable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    p.on_disable(state)
    proto = get_protocol(state, name)
    proto.enabled = False
    save_state(state)
    return apply_config(state)


def add_user(state: AppState, user: User) -> None:
    from hydra.core.state import add_user as _add
    _add(state, user)
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(user, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)


def remove_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_remove(u, state)
            except Exception:
                pass
    state.users = [x for x in state.users if x.email != email]
    save_state(state)
    apply_config(state)


def block_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    u.blocked = True
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_block(u, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)


def unblock_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    u.blocked = False
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(u, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)
