"""Per-protocol parameter entry for the node install wizard.

Each transport publishes its own public settings instead of one raw JSON box.
Only public parameters are collected: node-local secrets (keys, passwords,
tokens) are generated on the node and never travel from the base.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hydra.contracts.utls import UTLS_FINGERPRINTS
from hydra.contracts.vless_cdn import ENCRYPTION_MODES, MEDIA_MODE_LABELS, MEDIA_MODE_PHOTO, MEDIA_MODE_VIDEO
from hydra.ui.tui import confirm, error, menu, prompt


MAX_FIELD_ATTEMPTS = 3


@dataclass(frozen=True)
class NodeField:
    """One public protocol parameter asked in the node wizard."""

    key: str
    label: str
    kind: str = "text"  # text | int | bool | enum
    default: object = ""
    choices: tuple[tuple[str, str], ...] = ()
    hint: str = ""
    required: bool = False
    minimum: int | None = None
    maximum: int | None = None
    # Plugin module exposing ``list_presets()`` when the choices are dynamic.
    provider: str = ""


def _presets(module: str) -> tuple[tuple[str, str], ...]:
    """Expose a plugin's own obfuscation presets instead of a copied list."""
    from importlib import import_module

    listed = import_module(module).list_presets()
    return tuple((str(item["name"]), str(item.get("label") or item["name"])) for item in listed)


def _transport_choices() -> tuple[tuple[str, str], ...]:
    return (("tcp", "HTTP/2 (TCP)"), ("quic", "QUIC (UDP)"), ("both", "HTTP/2 + QUIC"))


PROTOCOL_FIELDS: dict[str, tuple[NodeField, ...]] = {
    "amneziawg": (
        NodeField(
            "protocol_mode",
            "Версия AmneziaWG",
            kind="enum",
            default="2.0",
            choices=(("2.0", "2.0 — базовая обфускация"), ("3.1", "3.1 — расширенная обфускация")),
        ),
    ),
    "anytls": (
        NodeField("domain", "Домен для AnyTLS", required=True, hint="A-запись уже должна указывать на эту ноду"),
        NodeField(
            "padding_preset",
            "Обфускация паддинга",
            kind="enum",
            choices=(),
            provider="hydra.plugins.anytls.presets",
        ),
    ),
    "calls": (),
    "hysteria2": (
        NodeField("domain", "Домен для Hysteria2", required=True),
        NodeField(
            "congestion_mode",
            "Congestion control",
            kind="enum",
            default="bbr",
            choices=(("bbr", "BBR — автоматическая оценка"), ("brutal", "Brutal — явные Mbps")),
        ),
        NodeField("up_mbps", "Upload, Mbps", kind="int", default=100, minimum=1, maximum=100000),
        NodeField("down_mbps", "Download, Mbps", kind="int", default=100, minimum=1, maximum=100000),
    ),
    "mieru": (
        NodeField(
            "traffic_preset",
            "Обфускация трафика",
            kind="enum",
            choices=(),
            provider="hydra.plugins.mieru.presets",
        ),
    ),
    "mtproto_zig": (
        NodeField("domain", "Домен FakeTLS", required=True),
        NodeField(
            "web_mode",
            "Режим WEB-ретранслятора",
            kind="enum",
            default="off",
            choices=(("off", "Выключен"), ("hybrid", "Hybrid — Telegram и WEB"), ("web-only", "Только WEB")),
        ),
        NodeField("web_domain", "Домен WEB-ретранслятора", hint="нужен только при включённом режиме"),
    ),
    "naive": (
        NodeField("domain", "Домен для NaiveProxy", required=True),
        NodeField("network", "Транспорт", kind="enum", default="tcp", choices=_transport_choices()),
        NodeField("uot", "UDP over TCP", kind="bool", default=True),
    ),
    "shadowtls": (
        NodeField("domain", "Домен ShadowTLS", required=True),
        NodeField("handshake_sni", "SNI-маскировка", hint="по умолчанию — домен ноды"),
    ),
    "snell": (
        NodeField(
            "obfs_mode",
            "Обфускация",
            kind="enum",
            default="none",
            choices=(("none", "Выключена"), ("http", "HTTP"), ("tls", "TLS")),
        ),
        NodeField("obfs_host", "Host для обфускации", default="www.bing.com"),
        NodeField(
            "mode",
            "Режим Snell v6",
            kind="enum",
            default="default",
            choices=(
                ("default", "default — штатный"),
                ("unshaped", "unshaped — без шейпинга"),
                ("unsafe-raw", "unsafe-raw — без обфускации v6"),
            ),
        ),
    ),
    "trusttunnel": (
        NodeField("domain", "Домен для TrustTunnel", required=True),
        NodeField("transport", "Транспорт", kind="enum", default="tcp", choices=_transport_choices()),
    ),
    "vless": (
        NodeField(
            "security",
            "Защита",
            kind="enum",
            default="tls",
            choices=(("tls", "TLS — свой домен и сертификат"), ("reality", "Reality — подмена чужого TLS")),
        ),
        NodeField("domain", "Домен для VLESS", hint="обязателен в режиме TLS"),
        NodeField(
            "xhttp_mode",
            "Режим XHTTP",
            kind="enum",
            default="stream-up",
            choices=(
                ("stream-up", "stream-up — загрузка потоком"),
                ("packet-up", "packet-up — загрузка POST-запросами"),
                ("stream-one", "stream-one — один поток"),
            ),
        ),
        NodeField("xhttp_path", "Путь XHTTP", default="/xhttp"),
        NodeField(
            "utls_fingerprint",
            "Отпечаток uTLS",
            kind="enum",
            default="none",
            choices=tuple((value, value) for value in UTLS_FINGERPRINTS),
        ),
    ),
    "vless_cdn": (
        NodeField("cdn_domain", "CDN-домен", required=True, hint="домен, который вводит клиент"),
        NodeField("origin_host", "Origin-имя", hint="под каким CDN ходит на эту ноду"),
        NodeField(
            "media_mode",
            "Режим медиа",
            kind="enum",
            default=MEDIA_MODE_VIDEO,
            choices=(
                (MEDIA_MODE_VIDEO, MEDIA_MODE_LABELS[MEDIA_MODE_VIDEO]),
                (MEDIA_MODE_PHOTO, MEDIA_MODE_LABELS[MEDIA_MODE_PHOTO]),
            ),
        ),
        NodeField(
            "encryption_mode",
            "Шифрование профиля",
            kind="enum",
            default="native",
            choices=tuple((value, value) for value in ENCRYPTION_MODES),
        ),
        NodeField("xhttp_path", "Путь XHTTP", default="/xhttp"),
    ),
    "wdtt": (),
}

# Fields whose choices come from a plugin module are resolved once, on first use.
_provider_cache: dict[str, tuple[tuple[str, str], ...]] = {}


def _choices(item: NodeField) -> tuple[tuple[str, str], ...]:
    provider = item.provider
    if not provider:
        return item.choices
    cached = _provider_cache.get(provider)
    if cached is None:
        cached = _presets(provider)
        _provider_cache[provider] = cached
    return cached


def _ask_choice(item: NodeField, current: object) -> str | None:
    choices = _choices(item)
    if not choices:
        return ""
    default = str(current if current not in (None, "") else item.default)
    options = []
    for index, (value, label) in enumerate(choices, 1):
        options.append((str(index), label, "текущий" if value == default else ""))
    options.append(("0", "Оставить как есть", ""))
    for _ in range(MAX_FIELD_ATTEMPTS):
        selected = menu(options, item.label.upper())
        if selected == "0":
            return default
        if selected.isdecimal() and 1 <= int(selected) <= len(choices):
            return choices[int(selected) - 1][0]
    error(f"{item.label}: выбор не распознан, оставляю текущее значение")
    return default


def _ask(item: NodeField, current: object) -> tuple[bool, object]:
    """Ask one field; the bool is False when the operator cancelled."""
    if item.kind == "bool":
        return True, confirm(item.label, default=bool(current if current is not None else item.default))
    if item.kind == "enum":
        value = _ask_choice(item, current)
        return value is not None, value
    shown = current if current not in (None, "") else item.default
    for _ in range(MAX_FIELD_ATTEMPTS):
        raw = prompt(f"{item.label} (0 — отмена)", str(shown)).strip()
        if raw == "0":
            return False, None
        if not raw:
            raw = str(shown)
        if item.kind != "int":
            if not raw and item.required:
                error(f"{item.label}: значение обязательно")
                continue
            return True, raw
        try:
            number = int(raw)
        except ValueError:
            error(f"{item.label}: нужно целое число")
            continue
        if item.minimum is not None and number < item.minimum or item.maximum is not None and number > item.maximum:
            error(f"{item.label}: допустимо от {item.minimum} до {item.maximum}")
            continue
        return True, number
    error(f"{item.label}: значения нет, настройка протокола отменена")
    return False, None


def collect_protocol_config(name: str, previous: dict) -> dict | None:
    """Collect one protocol's public parameters; None means the operator cancelled."""
    collected: dict = dict(previous)
    for item in PROTOCOL_FIELDS.get(name, ()):
        accepted, value = _ask(item, previous.get(item.key))
        if not accepted:
            return None
        if value not in (None, ""):
            collected[item.key] = value
    return collected


def missing_required(name: str, config: dict) -> str:
    """Return the label of the first required field that is still empty."""
    for item in PROTOCOL_FIELDS.get(name, ()):
        if item.required and not str(config.get(item.key, "") or "").strip():
            return item.label
    return ""


def protocol_field_names(name: str) -> tuple[str, ...]:
    return tuple(item.key for item in PROTOCOL_FIELDS.get(name, ()))


def protocol_field_labels(name: str) -> dict[str, str]:
    """Human-readable labels for the collected keys shown in the summary panel."""
    return {item.key: item.label for item in PROTOCOL_FIELDS.get(name, ())}


__all__ = [
    "PROTOCOL_FIELDS",
    "NodeField",
    "collect_protocol_config",
    "missing_required",
    "protocol_field_labels",
    "protocol_field_names",
]


def supports_fields(name: str) -> bool:
    return name in PROTOCOL_FIELDS
