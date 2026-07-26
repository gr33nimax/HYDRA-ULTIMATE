"""Small dependency-free formatting primitives for terminal adapters."""
from __future__ import annotations

from collections.abc import Mapping, Sequence


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"


def paint(value: str, code: str, *, color: bool) -> str:
    return f"{code}{value}{RESET}" if color else value


def label(value: object) -> str:
    return str(value).replace("_", " ").strip().capitalize()


def scalar(value: object) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, Mapping):
        if not value:
            return "none"
        return ", ".join(
            f"{key}={scalar(item)}"
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return ", ".join(scalar(item) for item in value) if value else "none"
    return str(value)


def mark(value: object) -> str:
    if value is True:
        return "ok"
    if value is False:
        return "fail"
    return "-"


def table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
) -> list[str]:
    rendered = [[scalar(cell) for cell in row] for row in rows]
    if not rendered:
        return ["  none"]
    widths = [
        max(
            len(str(headers[index])),
            *(len(row[index]) for row in rendered),
        )
        for index in range(len(headers))
    ]
    header = "  ".join(
        str(value).ljust(widths[index])
        for index, value in enumerate(headers)
    )
    separator = "  ".join("-" * width for width in widths)
    lines = [f"  {header}", f"  {separator}"]
    for row in rendered:
        lines.append(
            "  "
            + "  ".join(
                value.ljust(widths[index])
                for index, value in enumerate(row)
            ),
        )
    return lines


def section(lines: list[str], title: str, *, color: bool) -> None:
    if lines and lines[-1]:
        lines.append("")
    lines.append(paint(title, BOLD, color=color))


def generic_lines(
    value: object,
    *,
    indent: int = 0,
    skip: frozenset[str] = frozenset(),
) -> list[str]:
    prefix = " " * indent
    if not isinstance(value, Mapping):
        return [f"{prefix}{scalar(value)}"]

    lines: list[str] = []
    for key, item in value.items():
        if str(key) in skip:
            continue
        if isinstance(item, Mapping) and item:
            lines.append(f"{prefix}{label(key)}:")
            lines.extend(generic_lines(item, indent=indent + 2))
        elif (
            isinstance(item, Sequence)
            and not isinstance(item, (str, bytes, bytearray))
            and item
            and all(isinstance(row, Mapping) for row in item)
        ):
            lines.append(f"{prefix}{label(key)}:")
            for row in item:
                lines.append(
                    f"{prefix}  * "
                    + ", ".join(
                        f"{nested_key}={scalar(nested_value)}"
                        for nested_key, nested_value in row.items()
                    ),
                )
        elif (
            isinstance(item, Sequence)
            and not isinstance(item, (str, bytes, bytearray))
            and item
            and (
                len(item) > 3
                or sum(len(scalar(entry)) for entry in item) > 80
            )
        ):
            lines.append(f"{prefix}{label(key)}:")
            lines.extend(
                f"{prefix}  - {scalar(entry)}"
                for entry in item
            )
        else:
            lines.append(f"{prefix}{label(key)}: {scalar(item)}")
    return lines


__all__ = [
    "BOLD",
    "DIM",
    "GREEN",
    "RED",
    "YELLOW",
    "generic_lines",
    "mark",
    "paint",
    "scalar",
    "section",
    "table",
]
