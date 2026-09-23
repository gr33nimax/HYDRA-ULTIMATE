"""User-facing routing categories assembled from HYDRA rule sources.

The catalogue carries hundreds of sources; an operator routes *groups*. One
category is one destination: the menu writes the same target to every source in
it, and reports ``mixed`` when a category no longer agrees with itself (an
upstream update can add a source to a category that was already routed).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

DEFAULT_LOCAL_LIST = "default"
AI_GROUP = "ai"
LOCAL_GROUP = "local"
OTHER_GROUP = "other"

# Which way a category has to be routed to work at all: the RU group is reachable
# from a Russian address, while everything else in the catalogue is either
# blocked here or refuses Russian subnets and needs the foreign address WARP
# provides. Routing a category the wrong way is the failure operators actually
# hit, so the hint is part of the menu instead of folklore.
GROUP_DIRECTIONS = {
    "ru": "direct",
    "blocked": "warp",
    LOCAL_GROUP: "",
}
DEFAULT_DIRECTION = "warp"

GROUP_LABELS = {
    "blocked": "Заблокированное в РФ",
    LOCAL_GROUP: "Мои списки",
    OTHER_GROUP: "Прочее",
}

# Menu order: what an operator reaches for first, then the upstream catalogue.
GROUP_ORDER = (
    "blocked",
    "ru",
    "ai",
    "media",
    "social",
    "messengers",
    "gaming",
    "forums",
    "developer",
    "cloud",
    "cdn",
    "storage",
    "shopping",
    "finance",
    "education",
    "security",
    "platforms",
    "work",
    "tools",
    "adult",
    LOCAL_GROUP,
    OTHER_GROUP,
)


@dataclass(frozen=True)
class RoutingCategory:
    """One menu entry: a group of sources routed to a single destination."""

    key: str
    label: str
    description: str
    direction: str
    source_keys: tuple[str, ...]
    sources: tuple[str, ...]
    order: int

    def as_dict(self) -> dict:
        return asdict(self)


def _order(key: str) -> int:
    try:
        return GROUP_ORDER.index(key)
    except ValueError:
        return len(GROUP_ORDER)


def _group_label(group: str, entries: list[tuple[str, str, str]]) -> str:
    label = GROUP_LABELS.get(group)
    if label:
        return label
    for _, _, description in entries:
        if description:
            return description
    return group


def build_routing_catalog(
    external_lists: dict[str, dict[str, str]],
    local_lists: dict,
) -> list[RoutingCategory]:
    """Group every routable source into semantic categories.

    Sources arrive from the upstream catalogue carrying a group of their own;
    local lists are the operator's, except HYDRA's default domain list, which
    belongs with the AI services it names.
    """
    grouped: dict[str, list[tuple[str, str, str]]] = {}
    for key in sorted(external_lists):
        item = external_lists[key]
        if not isinstance(item, dict):
            continue
        grouped.setdefault(str(item.get("group") or OTHER_GROUP), []).append(
            (
                f"ext:{key}",
                str(item.get("name") or key),
                str(item.get("desc") or ""),
            ),
        )
    if isinstance(local_lists, dict):
        for name in sorted(local_lists):
            if not isinstance(local_lists[name], dict):
                continue
            group = AI_GROUP if name == DEFAULT_LOCAL_LIST else LOCAL_GROUP
            label = f"HYDRA: {name}" if name == DEFAULT_LOCAL_LIST else f"Свой список: {name}"
            grouped.setdefault(group, []).append((f"local:{name}", label, ""))

    categories = []
    for group, entries in grouped.items():
        ordered = sorted(entries)
        direction = GROUP_DIRECTIONS.get(group, DEFAULT_DIRECTION)
        categories.append(
            RoutingCategory(
                key=group,
                label=_group_label(group, ordered),
                description=(f"{len(ordered)} источников" + (f" · обычно → {direction.upper()}" if direction else "")),
                direction=direction,
                source_keys=tuple(key for key, _, _ in ordered),
                sources=tuple(label for _, label, _ in ordered),
                order=_order(group),
            ),
        )
    return sorted(categories, key=lambda item: (item.order, item.label.lower()))


def category_target(category: RoutingCategory, list_targets: dict) -> str:
    """Report one category's destination, or ``mixed`` when its sources differ."""
    targets = {str(list_targets.get(key) or "none") for key in category.source_keys}
    targets.discard("none")
    if not targets:
        return "none"
    if len(targets) == 1:
        return next(iter(targets))
    return "mixed"


def category_menu(
    external_lists: dict[str, dict[str, str]],
    list_targets: dict | None = None,
    local_lists: dict | None = None,
) -> list[dict]:
    """Build the menu payload: every category with its current destination."""
    targets = list_targets if isinstance(list_targets, dict) else {}
    categories = build_routing_catalog(
        external_lists,
        local_lists if isinstance(local_lists, dict) else {},
    )
    return [{**item.as_dict(), "target": category_target(item, targets)} for item in categories]


__all__ = [
    "DEFAULT_LOCAL_LIST",
    "GROUP_DIRECTIONS",
    "GROUP_ORDER",
    "RoutingCategory",
    "build_routing_catalog",
    "category_menu",
    "category_target",
]
