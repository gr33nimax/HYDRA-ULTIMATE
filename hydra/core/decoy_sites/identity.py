"""Deterministic per-installation identity for decoy sites.

Every renderer derives its brand, palette and wording from the domain that
serves the site. Two installations therefore never publish byte-identical
markup, while regenerating the same site stays reproducible.
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar


T = TypeVar("T")

_BRAND_HEADS = (
    "Northvale", "Aster", "Cobalt", "Harbor", "Lumen", "Kestrel",
    "Meridian", "Orchard", "Quartz", "Solace", "Vertex", "Larkin",
    "Ember", "Foxglove", "Granite", "Halcyon", "Ivory", "Juniper",
    "Marlow", "Pinecrest", "Redstone", "Sable", "Thistle", "Wexford",
)
_BRAND_TAILS = (
    "Labs", "Works", "Systems", "Studio", "Collective", "Group",
    "Digital", "Partners", "Foundry", "Supply", "Union", "Atelier",
)
_FIRST_NAMES = (
    "Adrian", "Beatrix", "Callum", "Daniela", "Elias", "Farah",
    "Gideon", "Helena", "Ivan", "Juno", "Karim", "Lena",
    "Milan", "Nadia", "Oscar", "Priya", "Rafael", "Sofia",
    "Tobias", "Vera",
)
_LAST_NAMES = (
    "Alvarez", "Brandt", "Castellan", "Delacroix", "Eriksen", "Falk",
    "Grieve", "Halvorsen", "Ibarra", "Janssen", "Kovac", "Lindqvist",
    "Moreau", "Novak", "Okafor", "Petrenko", "Rossi", "Sandoval",
    "Tarrant", "Vasquez",
)
_CITIES = (
    "Lisbon", "Tallinn", "Porto", "Ghent", "Aarhus", "Kraków",
    "Valencia", "Bristol", "Leipzig", "Trieste", "Bergen", "Utrecht",
    "Ljubljana", "Cork", "Malmö", "Turin",
)
_PALETTES = (
    ("#2f6fed", "#1d4ed8", "#eef3ff"),
    ("#e11d48", "#9f1239", "#fff1f3"),
    ("#0f8a6a", "#0b6650", "#eafaf4"),
    ("#7c3aed", "#5b21b6", "#f4efff"),
    ("#c2410c", "#9a3412", "#fff3ec"),
    ("#0369a1", "#075985", "#eaf6fd"),
    ("#b45309", "#92400e", "#fdf5e6"),
    ("#be185d", "#9d174d", "#fdf0f6"),
    ("#15803d", "#166534", "#eefbf1"),
    ("#4338ca", "#3730a3", "#eff0ff"),
)
_FONTS = (
    "Inter,ui-sans-serif,system-ui,-apple-system,sans-serif",
    "'Source Sans 3',Segoe UI,ui-sans-serif,system-ui,sans-serif",
    "'IBM Plex Sans',ui-sans-serif,system-ui,-apple-system,sans-serif",
    "Charter,Georgia,'Times New Roman',serif",
)
_RADII = ("4px", "8px", "12px", "16px")
_SURFACES = ("#ffffff", "#fdfdfc", "#fcfcfd")
_BACKDROPS = ("#f5f7fb", "#f7f6f3", "#f4f6f5", "#fafafa")


def _digest(*parts: str) -> int:
    payload = "|".join(parts).encode("utf-8")
    return int.from_bytes(
        hashlib.blake2b(payload, digest_size=8).digest(),
        "big",
    )


@dataclass(frozen=True)
class SiteIdentity:
    """Stable presentation identity derived from one seed."""

    seed: str
    domain: str
    brand: str
    person: str
    city: str
    accent: str
    accent_dark: str
    tint: str
    surface: str
    backdrop: str
    font: str
    radius: str
    founded: int

    def pick(self, salt: str, options: Sequence[T]) -> T:
        """Choose one option deterministically for this identity."""
        if not options:
            raise ValueError("decoy identity needs at least one option")
        return options[_digest(self.seed, salt) % len(options)]

    def number(self, salt: str, minimum: int, maximum: int) -> int:
        """Return a stable number in an inclusive range."""
        if minimum > maximum:
            raise ValueError("decoy identity range is inverted")
        span = maximum - minimum + 1
        return minimum + _digest(self.seed, salt) % span

    @property
    def email(self) -> str:
        return f"hello@{self.domain}"

    @property
    def slug(self) -> str:
        return self.brand.split(" ")[0].lower()

    @property
    def fingerprint(self) -> str:
        """Short digest identifying this identity in the site marker."""
        return hashlib.blake2b(
            self.seed.encode("utf-8"),
            digest_size=8,
        ).hexdigest()


def build_identity(domain: str) -> SiteIdentity:
    """Derive the presentation identity of the site serving ``domain``."""
    seed = str(domain or "").strip().lower().rstrip(".") or "localhost"
    accent, accent_dark, tint = _PALETTES[_digest(seed, "palette") % len(_PALETTES)]
    brand = " ".join(
        (
            _BRAND_HEADS[_digest(seed, "brand-head") % len(_BRAND_HEADS)],
            _BRAND_TAILS[_digest(seed, "brand-tail") % len(_BRAND_TAILS)],
        ),
    )
    person = " ".join(
        (
            _FIRST_NAMES[_digest(seed, "first") % len(_FIRST_NAMES)],
            _LAST_NAMES[_digest(seed, "last") % len(_LAST_NAMES)],
        ),
    )
    return SiteIdentity(
        seed=seed,
        domain=seed,
        brand=brand,
        person=person,
        city=_CITIES[_digest(seed, "city") % len(_CITIES)],
        accent=accent,
        accent_dark=accent_dark,
        tint=tint,
        surface=_SURFACES[_digest(seed, "surface") % len(_SURFACES)],
        backdrop=_BACKDROPS[_digest(seed, "backdrop") % len(_BACKDROPS)],
        font=_FONTS[_digest(seed, "font") % len(_FONTS)],
        radius=_RADII[_digest(seed, "radius") % len(_RADII)],
        founded=2011 + _digest(seed, "founded") % 12,
    )


__all__ = ["SiteIdentity", "build_identity"]
