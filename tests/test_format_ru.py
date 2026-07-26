"""Contracts for the shared Russian formatting primitives."""
from __future__ import annotations

from hydra.utils.format_ru import (
    format_age,
    format_count,
    format_duration,
    plural,
    progress_bar,
)


def test_plural_selects_the_right_russian_form():
    forms = ("адрес", "адреса", "адресов")
    assert plural(1, forms) == "1 адрес"
    assert plural(2, forms) == "2 адреса"
    assert plural(5, forms) == "5 адресов"
    assert plural(11, forms) == "11 адресов"
    assert plural(21, forms) == "21 адрес"
    assert plural(112, forms) == "112 адресов"
    assert plural(None, forms) == "0 адресов"


def test_format_duration_uses_two_units_at_most():
    assert format_duration(0) == "0с"
    assert format_duration(45) == "45с"
    assert format_duration(600) == "10м"
    assert format_duration(605) == "10м 5с"
    assert format_duration(3600) == "1ч"
    assert format_duration(85200) == "23ч 40м"
    assert format_duration(86400) == "1д"
    assert format_duration(97200) == "1д 3ч"
    assert format_duration("broken") == "—"


def test_format_age_is_relative_to_the_supplied_instant():
    assert format_age(1000, now=1002) == "только что"
    assert format_age(1000, now=1120) == "2м назад"
    assert format_age(0, now=1000) == "—"
    assert format_age(1000, now=None) == "—"


def test_format_count_groups_thousands():
    assert format_count(18432) == "18 432"
    assert format_count(7) == "7"
    assert format_count(None) == "0"
    assert format_count("broken") == "0"


def test_progress_bar_is_clamped_and_degrades_safely():
    assert progress_bar(0, maximum=8, width=4) == "░░░░"
    assert progress_bar(4, maximum=8, width=4) == "██░░"
    assert progress_bar(99, maximum=8, width=4) == "████"
    assert progress_bar(1, maximum=0, width=4) == "████"
    assert progress_bar("broken", maximum=8, width=4) == "░░░░"
