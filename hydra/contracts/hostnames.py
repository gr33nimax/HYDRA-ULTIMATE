"""Hostname validation for public names that reach SNI and ACME.

Публичное имя попадает и в SNI-маршрут мультиплексора, и в запрос сертификата,
поэтому проверяется один раз здесь, а не отдельной копией правил в каждом
протоколе. Модуль намеренно не зависит от верхних слоёв.
"""

from __future__ import annotations

import re

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def normalize_hostname(value: object, *, field: str) -> str:
    """Return a lowercase hostname suitable for SNI and for an ACME HTTP-01 challenge."""
    host = str(value or "").strip().rstrip(".")
    if not host:
        raise ValueError(f"{field} не задан")
    if "://" in host or "/" in host or any(character.isspace() for character in host):
        raise ValueError(f"{field} должен быть именем хоста без схемы и пути")
    if len(host) > 253:
        raise ValueError(f"{field} слишком длинный")

    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.match(label) for label in labels):
        raise ValueError(
            f"{field} должен быть доменным именем, например origin.example.com",
        )
    return host.lower()


__all__ = ["normalize_hostname"]
