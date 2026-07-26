"""External routing-list catalog refresh and cache persistence."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Callable
import urllib.request

from hydra.plugins.context import PluginStateAccess


def enabled_external_keys(state: PluginStateAccess) -> list[str]:
    plugin_state = state.protocols.get("warp")
    if not plugin_state:
        return []
    result = []
    for list_key, target in plugin_state.config.get("list_targets", {}).items():
        if list_key.startswith("ext:") and target and target != "none":
            key = list_key.split(":", 1)[1]
            if key not in result:
                result.append(key)
    return result


def parse_rule_list(
    content: str,
    *,
    validate_ip: Callable[[str], bool],
    validate_domain: Callable[[str], bool],
) -> dict[str, list[str]]:
    domains, ips = [], []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        for token in line.split():
            token = token.strip()
            if validate_ip(token):
                ips.append(token)
            elif validate_domain(token):
                domains.append(token)
    return {"domains": sorted(set(domains)), "ips": sorted(set(ips))}


def download_rule_lists(
    enabled_keys: list[str],
    catalog: dict[str, dict[str, str]],
    *,
    validate_ip: Callable[[str], bool],
    validate_domain: Callable[[str], bool],
) -> tuple[dict, list[str]]:
    downloaded = {}
    errors = []
    for key in enabled_keys:
        if key not in catalog:
            errors.append(f"Неизвестный источник: {key}")
            continue
        item = catalog[key]
        try:
            request = urllib.request.Request(
                item["url"],
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read().decode("utf-8", errors="replace")
            downloaded[key] = parse_rule_list(
                content,
                validate_ip=validate_ip,
                validate_domain=validate_domain,
            )
        except Exception as exc:
            errors.append(f"{item['name']}: {exc}")
    return downloaded, errors


def _load_existing_cache(cache: Path) -> dict:
    if not cache.exists():
        return {}
    try:
        existing = json.loads(cache.read_text(encoding="utf-8"))
        if "domains" in existing and not isinstance(existing["domains"], dict):
            return {}
        return existing
    except Exception:
        return {}


def persist_rule_cache(
    downloaded: dict,
    enabled_keys: list[str],
    errors: list[str],
    *,
    cache: Path,
    host: Any,
) -> None:
    existing = _load_existing_cache(cache)
    existing.update(downloaded)
    metadata = {"updated_at", "last_attempt_at"}
    for key in list(existing):
        if key not in metadata and key not in enabled_keys:
            existing.pop(key, None)
    attempted_at = datetime.now().isoformat()
    existing["last_attempt_at"] = attempted_at
    if errors:
        existing.pop("updated_at", None)
    else:
        existing["updated_at"] = attempted_at
    host.atomic_write(
        cache,
        json.dumps(existing, indent=2, ensure_ascii=False),
        mode=0o600,
    )


def update_external_rules(
    state: PluginStateAccess,
    *,
    catalog: dict[str, dict[str, str]],
    cache: Path,
    host: Any,
    validate_ip: Callable[[str], bool],
    validate_domain: Callable[[str], bool],
) -> tuple[bool, str]:
    if "warp" not in state.protocols:
        return False, "Плагин не настроен в state.json"
    keys = enabled_external_keys(state)
    if not keys:
        if cache.exists():
            try:
                cache.unlink()
            except Exception:
                pass
        return True, "Нет активных внешних списков"

    downloaded, errors = download_rule_lists(
        keys,
        catalog,
        validate_ip=validate_ip,
        validate_domain=validate_domain,
    )
    if not downloaded:
        message = "Ошибка обновления списков."
        if errors:
            message += f" Ошибки: {'; '.join(errors)}"
        return False, message
    try:
        persist_rule_cache(downloaded, keys, errors, cache=cache, host=host)
    except Exception as exc:
        return False, f"Ошибка сохранения кэша: {exc}"

    message = f"Обновлено списков: {len(downloaded)}/{len(keys)}."
    if errors:
        message += f" Ошибки: {'; '.join(errors)}"
    return not errors, message


__all__ = [
    "download_rule_lists",
    "enabled_external_keys",
    "parse_rule_list",
    "update_external_rules",
]
