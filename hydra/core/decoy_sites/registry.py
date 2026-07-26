"""Catalogue of decoy-site themes available to protocols with a decoy."""
from __future__ import annotations

from dataclasses import dataclass

from hydra.core.decoy_sites import (
    apidocs,
    blog,
    cafe,
    conference,
    docs,
    gallery,
    landing,
    media,
    portfolio,
    shop,
    status,
)
from hydra.core.decoy_sites.builder import Renderer


@dataclass(frozen=True)
class DecoyTheme:
    """One selectable decoy site."""

    name: str
    label: str
    description: str
    render: Renderer


THEMES: dict[str, DecoyTheme] = {
    theme.name: theme
    for theme in (
        DecoyTheme(
            "landing",
            "Студия и агентство",
            "Лендинг digital-студии с услугами и контактами",
            landing.generate,
        ),
        DecoyTheme(
            "blog",
            "Личный блог",
            "Инженерные заметки с двумя статьями и страницей об авторе",
            blog.generate,
        ),
        DecoyTheme(
            "docs",
            "Документация продукта",
            "Справка по установке и настройке с боковым меню",
            docs.generate,
        ),
        DecoyTheme(
            "media",
            "Цифровое издание",
            "Новостной сайт с разделами и статьёй",
            media.generate,
        ),
        DecoyTheme(
            "status",
            "Статус сервиса",
            "Страница доступности с компонентами и историей инцидентов",
            status.generate,
        ),
        DecoyTheme(
            "portfolio",
            "Портфолио специалиста",
            "Личный сайт дизайнера с работами и резюме",
            portfolio.generate,
        ),
        DecoyTheme(
            "shop",
            "Интернет-магазин",
            "Небольшой каталог товаров, карточка и доставка",
            shop.generate,
        ),
        DecoyTheme(
            "apidocs",
            "API-справочник",
            "Тёмная документация API с примерами запросов",
            apidocs.generate,
        ),
        DecoyTheme(
            "conference",
            "Конференция",
            "Лендинг мероприятия с программой и площадкой",
            conference.generate,
        ),
        DecoyTheme(
            "gallery",
            "Фотогалерея",
            "Тёмное портфолио фотографа с сеткой работ",
            gallery.generate,
        ),
        DecoyTheme(
            "cafe",
            "Кафе",
            "Сайт городского кафе с меню и часами работы",
            cafe.generate,
        ),
    )
}

THEME_NAMES: tuple[str, ...] = tuple(THEMES)


def get_theme(name: object) -> DecoyTheme:
    """Return one declared theme or reject the operator input."""
    key = str(name or "").strip().lower()
    theme = THEMES.get(key)
    if theme is None:
        raise ValueError(f"Unknown decoy theme: {name}")
    return theme


def is_supported(name: object) -> bool:
    """Report whether a theme name is part of the catalogue."""
    return str(name or "").strip().lower() in THEMES


__all__ = ["THEMES", "THEME_NAMES", "DecoyTheme", "get_theme", "is_supported"]
