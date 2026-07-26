"""Validated XHTTP transport tuning shared by the VLESS plugin surfaces."""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass


DEFAULT_MODE = "stream-up"
DEFAULT_PATH = "/xhttp"
XHTTP_MODES = frozenset({"stream-up", "packet-up", "stream-one"})

_RANGE = re.compile(r"[0-9]{1,6}(?:-[0-9]{1,6})?")
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
_RESERVED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "transfer-encoding",
        "upgrade",
    },
)
_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"false", "0", "no", "off"})
_MAX_HEADERS = 16
_MAX_HEADER_VALUE = 256


def validate_path(value: object) -> str:
    """Return a safe XHTTP URL path or reject the operator input."""
    path = str(value or "").strip()
    segments = path.split("/")[1:]
    if (
        not path.startswith("/")
        or path == "/"
        or len(path) > 256
        or any(character.isspace() for character in path)
        or any(character in path for character in "?#*%\\")
        or any(
            segment in {"", ".", ".."}
            or not re.fullmatch(r"[A-Za-z0-9._~-]+", segment)
            for segment in segments
        )
    ):
        raise ValueError(
            "XHTTP path must start with '/', identify a non-root path, "
            "and contain no whitespace, query, or fragment",
        )
    return path.rstrip("/")


def validate_mode(value: object) -> str:
    """Return a supported XHTTP transport mode."""
    mode = str(value or "").strip().lower()
    if mode not in XHTTP_MODES:
        allowed = ", ".join(sorted(XHTTP_MODES))
        raise ValueError(f"XHTTP mode must be one of: {allowed}")
    return mode


def _validate_range(value: object, *, field: str, maximum: int) -> str:
    text = str(value if value is not None else "").strip()
    if not _RANGE.fullmatch(text):
        raise ValueError(f"{field} must be 'N' or 'N-M'")
    bounds = [int(part) for part in text.split("-")]
    if any(bound > maximum for bound in bounds) or bounds[0] > bounds[-1]:
        raise ValueError(
            f"{field} must be an ascending range within 0-{maximum}",
        )
    return text


def _validate_int(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{field} must be an integer") from None
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} must be within {minimum}-{maximum}")
    return number


def _validate_bool(value: object, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"{field} must be a boolean")


def validate_headers(value: object) -> dict[str, str]:
    """Return sorted extra HTTP headers safe for the XHTTP transport."""
    if not isinstance(value, Mapping):
        raise ValueError("XHTTP headers must be a JSON object")
    if len(value) > _MAX_HEADERS:
        raise ValueError(
            f"XHTTP headers must not exceed {_MAX_HEADERS} entries",
        )
    headers: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError(f"XHTTP header name is invalid: {raw_name!r}")
        if name.lower() in _RESERVED_HEADERS:
            raise ValueError(
                f"XHTTP header {name} is managed by the transport",
            )
        text = str(raw_value)
        if (
            not text
            or len(text) > _MAX_HEADER_VALUE
            or any(character < " " or character == "\x7f" for character in text)
        ):
            raise ValueError(f"XHTTP header value is invalid for {name}")
        headers[name] = text
    return dict(sorted(headers.items()))


@dataclass(frozen=True)
class TuningField:
    """One operator-tunable XHTTP transport knob."""

    param: str
    key: str
    transport: str
    link: str
    label: str
    hint: str
    default: object
    validate: Callable[[object], object]


FIELDS: tuple[TuningField, ...] = (
    TuningField(
        "headers",
        "xhttp_headers",
        "headers",
        "headers",
        "HTTP-заголовки",
        f"до {_MAX_HEADERS} пар, имена транспорта запрещены",
        {},
        validate_headers,
    ),
    TuningField(
        "padding",
        "xhttp_padding",
        "x_padding_bytes",
        "xPaddingBytes",
        "Паддинг запросов",
        "диапазон байт 0-65535, '0' отключает",
        "100-1000",
        lambda value: _validate_range(
            value,
            field="XHTTP padding",
            maximum=65535,
        ),
    ),
    TuningField(
        "no_sse_header",
        "xhttp_no_sse_header",
        "no_sse_header",
        "noSSEHeader",
        "Без SSE-заголовка",
        "для CDN и посредников с буферизацией",
        False,
        lambda value: _validate_bool(value, field="XHTTP no_sse_header"),
    ),
    TuningField(
        "max_post_bytes",
        "xhttp_max_post_bytes",
        "sc_max_each_post_bytes",
        "scMaxEachPostBytes",
        "Размер upload-пакета",
        "4096-16777216 байт",
        1_000_000,
        lambda value: _validate_int(
            value,
            field="XHTTP max_post_bytes",
            minimum=4096,
            maximum=16_777_216,
        ),
    ),
    TuningField(
        "max_buffered_posts",
        "xhttp_max_buffered_posts",
        "sc_max_buffered_posts",
        "scMaxBufferedPosts",
        "Буфер upload-пакетов",
        "1-1024 пакетов",
        30,
        lambda value: _validate_int(
            value,
            field="XHTTP max_buffered_posts",
            minimum=1,
            maximum=1024,
        ),
    ),
    TuningField(
        "stream_up_secs",
        "xhttp_stream_up_secs",
        "sc_stream_up_server_secs",
        "scStreamUpServerSecs",
        "Длительность stream-up",
        "диапазон секунд 0-3600",
        "20-80",
        lambda value: _validate_range(
            value,
            field="XHTTP stream_up_secs",
            maximum=3600,
        ),
    ),
    TuningField(
        "max_header_bytes",
        "xhttp_max_header_bytes",
        "server_max_header_bytes",
        "",
        "Лимит заголовков запроса",
        "1024-65536 байт, только сервер",
        8192,
        lambda value: _validate_int(
            value,
            field="XHTTP max_header_bytes",
            minimum=1024,
            maximum=65536,
        ),
    ),
)

FIELDS_BY_PARAM: dict[str, TuningField] = {
    field.param: field for field in FIELDS
}

TUNING_DEFAULTS: tuple[tuple[str, object], ...] = tuple(
    (field.key, field.default) for field in FIELDS
)


def effective(config: Mapping[str, object]) -> dict[str, object]:
    """Return validated tuning values, falling back to plugin defaults."""
    values: dict[str, object] = {}
    for field in FIELDS:
        raw = config.get(field.key, field.default)
        values[field.key] = field.validate(raw)
    return values


def transport(
    config: Mapping[str, object],
    *,
    client: bool,
    domain: str = "",
) -> dict[str, object]:
    """Build the sing-box XHTTP transport block for either side."""
    values = effective(config)
    block: dict[str, object] = {
        "type": "xhttp",
        "mode": validate_mode(config.get("xhttp_mode", DEFAULT_MODE)),
        "host": domain if client else "",
        "path": validate_path(config.get("xhttp_path", DEFAULT_PATH)),
    }
    for field in FIELDS:
        block[field.transport] = values[field.key]
    if not client:
        block["trusted_x_forwarded_for"] = []
    return block


def link_extra(config: Mapping[str, object]) -> dict[str, object]:
    """Return client-visible tuning that differs from the defaults."""
    values = effective(config)
    return {
        field.link: values[field.key]
        for field in FIELDS
        if field.link and values[field.key] != field.default
    }


def apply_settings(
    config: dict[str, object],
    parameters: Mapping[str, object],
) -> None:
    """Validate every supplied knob before mutating the desired config."""
    unknown = sorted(set(parameters) - set(FIELDS_BY_PARAM))
    if unknown:
        raise ValueError(
            f"unsupported XHTTP tuning parameters: {', '.join(unknown)}",
        )
    if not parameters:
        raise ValueError("no XHTTP tuning parameters supplied")
    validated = {
        FIELDS_BY_PARAM[param].key: FIELDS_BY_PARAM[param].validate(value)
        for param, value in parameters.items()
    }
    config.update(validated)


def summary(config: Mapping[str, object]) -> str:
    """Return a compact operator-facing description of the tuning."""
    values = effective(config)
    headers = values["xhttp_headers"]
    return " · ".join(
        [
            f"padding {values['xhttp_padding']}",
            f"post {values['xhttp_max_post_bytes']}B",
            f"buffer {values['xhttp_max_buffered_posts']}",
            f"stream-up {values['xhttp_stream_up_secs']}s",
            f"headers {len(headers)}" if headers else "headers нет",
        ],
    )


__all__ = [
    "DEFAULT_MODE",
    "DEFAULT_PATH",
    "FIELDS",
    "FIELDS_BY_PARAM",
    "TUNING_DEFAULTS",
    "TuningField",
    "XHTTP_MODES",
    "apply_settings",
    "effective",
    "link_extra",
    "summary",
    "transport",
    "validate_headers",
    "validate_mode",
    "validate_path",
]
