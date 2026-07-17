"""User-facing routing categories assembled from every WARP rule source."""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RoutingCategory:
    key: str
    label: str
    description: str
    source_keys: tuple[str, ...]
    sources: tuple[str, ...]
    order: int = 500


_KNOWN = (
    ("geoblock", "Обход блокировок", "Ресурсы, ограниченные по географии или заблокированные в РФ", 10,
     ("geoblock", "geo-block", "blocked", "blocklist", "заблок", "геоблок")),
    ("ru_services", "Российские сервисы", "Сервисы, которым нужен российский IP-адрес", 20,
     ("russia", "russian", "ru-service", "ru_service", "category-ru", "рф-сервис", "росси")),
    ("google_ai", "Google AI", "Gemini, AI Studio и другие AI-сервисы Google", 30,
     ("google-ai", "google_ai", "googleai", "gemini")),
    ("ai", "AI-сервисы", "ChatGPT, Claude и другие сервисы искусственного интеллекта", 40,
     ("artificial-intelligence", "ai-services", "ai_service", "chatgpt", "openai", "claude", " ии ")),
    ("youtube", "YouTube", "Видео, API и вспомогательные домены YouTube", 50,
     ("youtube",)),
    ("streaming", "Видео и стриминг", "Стриминговые платформы и видеосервисы", 60,
     ("streaming", "stream", "video", "netflix", "spotify")),
    ("messengers", "Мессенджеры", "Мессенджеры, голосовые вызовы и связанные CDN", 70,
     ("messenger", "discord", "telegram", "whatsapp", "signal")),
    ("social", "Социальные сети", "Социальные сети и их медиаресурсы", 80,
     ("social", "instagram", "facebook", "twitter", "tiktok", "meta")),
    ("games", "Игры", "Игровые сервисы, магазины и серверы", 90,
     ("gaming", "games", "steam", "playstation", "xbox", "игры")),
    ("torrents", "Торренты", "Торрент-трекеры и связанные ресурсы", 95,
     ("torrent",)),
    ("privacy", "Реклама и трекеры", "Рекламные, аналитические и отслеживающие домены", 100,
     ("advert", "ads", "tracker", "tracking", "privacy")),
    ("private", "Локальные сети", "Частные адреса и локальные домены; обычно направляются напрямую", 110,
     ("private-ip", "private-domain", "private-network", "lan")),
)


def _normalise(value: str) -> str:
    value = value.strip().lower().replace("_", "-")
    return re.sub(r"[^a-zа-яё0-9]+", "-", value).strip("-")


def _identity(label: str, name: str) -> tuple[str, str, str, int]:
    normalised_label = _normalise(label)
    normalised_name = _normalise(name)
    # Clash group is the author's intended user-facing category. Prefer it over
    # individual provider names unless it is merely a technical catch-all.
    group_haystack = f" {normalised_label} "
    generic_group = normalised_label in ("", "без-группы", "direct", "proxy")
    haystack = f"{group_haystack} {normalised_name}"
    for key, title, description, order, aliases in _KNOWN:
        if not generic_group and any(alias in group_haystack for alias in aliases):
            return key, title, description, order
    for key, title, description, order, aliases in _KNOWN:
        if any(alias in haystack for alias in aliases) or (key == "ai" and normalised_name == "ai"):
            return key, title, description, order
    raw = label if label and label.lower() not in ("без группы", "direct", "proxy") else name
    title = raw.replace("_", " ").replace("-", " ").strip()
    title = title[:1].upper() + title[1:] if title else "Другая категория"
    key = "custom-" + (_normalise(raw) or "other")
    return key, title, "Категория из загруженной конфигурации", 300


def build_routing_catalog(
    bundle: dict | None,
    external_lists: dict,
    local_lists: dict,
) -> list[RoutingCategory]:
    """Merge YAML providers, built-ins and local lists into semantic categories."""
    grouped: dict[str, dict] = {}

    def add(source_key: str, name: str, group: str, origin: str, description: str = "") -> None:
        key, label, default_description, order = _identity(group, name)
        item = grouped.setdefault(key, {
            "label": label,
            "description": default_description if order < 300 else (description or default_description),
            "source_keys": [],
            "sources": [],
            "order": order,
        })
        if source_key not in item["source_keys"]:
            item["source_keys"].append(source_key)
            item["sources"].append(origin)
        if item["description"] == "Категория из загруженной конфигурации" and description:
            item["description"] = description

    for name, data in external_lists.items():
        add(f"ext:{name}", str(data.get("name", name)), name, "каталог HYDRA", str(data.get("desc", "")))

    for provider in (bundle or {}).get("rule_providers", []):
        if not provider.get("supported") or not provider.get("name"):
            continue
        name = str(provider["name"])
        group = str(provider.get("route_group") or name)
        add(f"yaml:{name}", name, group, f"загруженный конфиг: {name}")

    for name in local_lists:
        if name == "default":
            add(f"local:{name}", str(name), "ai-services", "стартовый набор HYDRA")
        else:
            add(f"local:{name}", str(name), str(name), f"свой список: {name}", "Пользовательские домены и IP-адреса")

    return sorted((
        RoutingCategory(
            key=key,
            label=value["label"],
            description=value["description"],
            source_keys=tuple(value["source_keys"]),
            sources=tuple(value["sources"]),
            order=value["order"],
        )
        for key, value in grouped.items()
    ), key=lambda item: (item.order, item.label.lower()))


def category_target(category: RoutingCategory, list_targets: dict) -> str:
    targets = {list_targets.get(key, "none") for key in category.source_keys}
    return next(iter(targets)) if len(targets) == 1 else "mixed"
