"""ShadowTLS-specific setup widgets kept outside generic protocol UI."""
from __future__ import annotations

from collections.abc import Callable

from hydra.plugins.shadowtls.constants import SHADOWTLS_SNI_PRESETS
from hydra.ui.tui import menu, prompt


def choose_shadowtls_sni(
    *,
    choose: Callable[..., str] = menu,
    ask: Callable[..., str] = prompt,
) -> str:
    """Choose a curated TLS 1.3 SNI or collect a custom value."""
    options = [
        (str(index), domain, label)
        for index, (domain, label) in enumerate(
            SHADOWTLS_SNI_PRESETS,
            start=1,
        )
    ]
    custom_key = str(len(options) + 1)
    options.extend(
        [
            (custom_key, "Свой домен", "Введите произвольный TLS 1.3 SNI"),
            ("0", "Отмена", ""),
        ],
    )
    choice = choose(options, "SNI ДЛЯ SHADOWTLS")
    if choice == "0":
        return ""
    if choice == custom_key:
        return ask("Введите сторонний TLS 1.3 домен").strip()
    try:
        return SHADOWTLS_SNI_PRESETS[int(choice) - 1][0]
    except (ValueError, IndexError):
        return ""


__all__ = ["choose_shadowtls_sni"]
