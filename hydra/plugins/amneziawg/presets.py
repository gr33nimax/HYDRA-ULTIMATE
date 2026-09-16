"""
hydra/plugins/amneziawg/presets.py — Carrier-пресеты и стратегии обфускации для AmneziaWG.
"""

from __future__ import annotations
import random
from typing import Optional, Any
from dataclasses import dataclass


@dataclass
class Strategy:
    label: str
    description: str
    jc_range: tuple[int, int]
    jmin_range: tuple[int, int]
    jmax_delta_range: tuple[int, int]
    s1_range: tuple[int, int]
    s2_range: tuple[int, int]
    s3_range: tuple[int, int]
    s4_range: tuple[int, int]
    h_randomize: bool
    i1_mode: str  # "random" | "absent"


@dataclass
class CarrierOverride:
    label: str
    description: str
    base_strategy: str
    jc_range: tuple[int, int] | None = None
    jmin_range: tuple[int, int] | None = None
    jmax_delta_range: tuple[int, int] | None = None
    s1_range: tuple[int, int] | None = None
    s2_range: tuple[int, int] | None = None
    i1_mode: str | None = None


STRATEGIES: dict[str, Strategy] = {
    "wired": Strategy(
        label="🏠 Проводной интернет",
        description="Универсальный пресет для проводного/оптического интернета. Широкий диапазон Jc, умеренный джиттер.",
        jc_range=(4, 8),
        jmin_range=(40, 100),
        jmax_delta_range=(80, 300),
        s1_range=(20, 120),
        s2_range=(20, 120),
        s3_range=(0, 0),
        s4_range=(4, 8),
        h_randomize=True,
        i1_mode="random",
    ),
    "mobile": Strategy(
        label="📱 Мобильный интернет",
        description="Для мобильных операторов с ТСПУ. Jc=3 фиксированный, узкий джиттер. Работает на большинстве операторов.",
        jc_range=(3, 3),
        jmin_range=(30, 50),
        jmax_delta_range=(20, 80),
        s1_range=(15, 80),
        s2_range=(15, 80),
        s3_range=(0, 0),
        s4_range=(2, 6),
        h_randomize=True,
        i1_mode="random",
    ),
    "stealth": Strategy(
        label="🥷 Максимальная обфускация",
        description="Все параметры рандомизируются. Максимальная устойчивость к DPI, возможно снижение скорости.",
        jc_range=(5, 8),
        jmin_range=(40, 120),
        jmax_delta_range=(100, 400),
        s1_range=(50, 150),
        s2_range=(50, 150),
        s3_range=(8, 55),
        s4_range=(8, 24),
        h_randomize=True,
        i1_mode="random",
    ),
    "low_latency": Strategy(
        label="⚡ Низкая задержка (игры/звонки)",
        description="Минимум обфускации и накладных расходов для минимизации задержек.",
        jc_range=(2, 3),
        jmin_range=(20, 40),
        jmax_delta_range=(10, 30),
        s1_range=(5, 15),
        s2_range=(5, 15),
        s3_range=(0, 0),
        s4_range=(0, 0),
        h_randomize=True,
        i1_mode="random",
    ),
}

CARRIER_OVERRIDES: dict[str, CarrierOverride] = {
    "tele2": CarrierOverride(
        label="Tele2",
        description="Jc=3 строго обязателен, узкий диапазон Jmax.",
        base_strategy="mobile",
        jc_range=(3, 3),
        jmax_delta_range=(20, 80),
        i1_mode="random",
    ),
    "mts": CarrierOverride(
        label="МТС",
        description="Jc=3, стандартная мобильная стратегия.",
        base_strategy="mobile",
        jc_range=(3, 3),
        i1_mode="random",
    ),
    "megafon": CarrierOverride(
        label="Мегафон",
        description="Параметр I1 должен отсутствовать, иначе соединение блокируется в регионах.",
        base_strategy="mobile",
        jc_range=(3, 3),
        i1_mode="absent",
    ),
    "yota": CarrierOverride(
        label="Yota",
        description="Узкий диапазон Jmax < 300.",
        base_strategy="mobile",
        jc_range=(3, 3),
        jmax_delta_range=(20, 80),
        i1_mode="random",
    ),
    "beeline": CarrierOverride(
        label="Билайн",
        description="Слабая фильтрация, используется проводная стратегия.",
        base_strategy="wired",
    ),
}

LEGACY_PRESET_MAP = {
    "default": ("wired", None),
    "mobile": ("mobile", None),
    "tele2": ("mobile", "tele2"),
    "yota": ("mobile", "yota"),
    "megafon": ("mobile", "megafon"),
    "beeline": ("wired", "beeline"),
    "tattelecom": ("mobile", "tele2"),  # Таттелеком мапится на Tele2 для обратной совместимости
}

# Для совместимости, если внешние модули читают ключи напрямую
CARRIER_PRESETS: dict[str, dict] = {
    "default": {
        "label": "Default (проводной интернет)",
        "jc_min": 3,
        "jc_max": 6,
        "jmin_min": 40,
        "jmin_max": 89,
        "jmax_delta_min": 50,
        "jmax_delta_max": 250,
        "i1_mode": "random",
        "description": "Универсальный пресет для проводного интернета.",
    },
    "mobile": {
        "label": "Mobile (универсальный для мобильных DPI)",
        "jc_min": 3,
        "jc_max": 3,
        "jmin_min": 30,
        "jmin_max": 50,
        "jmax_delta_min": 20,
        "jmax_delta_max": 80,
        "i1_mode": "random",
        "description": "Jc=3 фиксированный, узкий Jmax. Для мобильных с ТСПУ.",
    },
}

JC_MIN = 1
JC_MAX = 128
JMIN_MAX = 1280
JMAX_MAX = 1280
S3_MAX = 64
S4_MAX = 32

# In 3.x the padding of every packet type carries the material the header protection is built
# from, so each type needs a padding at least as large as its nonce. That minimum is the whole
# 3.x requirement: upstream asks for identical values only once RandomTrailers is on, and the
# server owns those values. The 2.0 ranges draw per type and allow zeros — legal there.
AWG3_PADDING_MIN = 12


def _awg3_range(span: tuple[int, int]) -> tuple[int, int]:
    """Raise only the lower bound of one preset range to the header-protection nonce."""
    low, high = span
    return max(low, AWG3_PADDING_MIN), max(high, AWG3_PADDING_MIN)


def _draw_paddings(
    local_random: Any,
    *,
    protocol_mode: str,
    s1_range: tuple[int, int],
    s2_range: tuple[int, int],
    s3_range: tuple[int, int],
    s4_range: tuple[int, int],
) -> tuple[int, int, int, int]:
    """Draw the four packet paddings for one strategy.

    For 3.x each field keeps its own preset range with the nonce minimum applied, because equal
    paddings are an upstream recommendation only while RandomTrailers is on, not a protocol rule.
    A range that cannot reach the minimum is lifted to it rather than replaced wholesale.
    """
    if str(protocol_mode).strip() not in ("", "2.0"):
        s1_range = _awg3_range(s1_range)
        s2_range = _awg3_range(s2_range)
        s3_range = _awg3_range(s3_range)
        s4_range = _awg3_range(s4_range)
    s1 = local_random.randint(s1_range[0], s1_range[1])
    s2 = local_random.randint(s2_range[0], s2_range[1])
    while s1 + 56 == s2:
        s2 = local_random.randint(s2_range[0], s2_range[1])
    s3 = local_random.randint(s3_range[0], s3_range[1])
    s4 = local_random.randint(s4_range[0], s4_range[1])
    return s1, s2, s3, s4


def generate_params(
    strategy: str = "wired",
    carrier: str | None = None,
    seed: int | None = None,
    protocol_mode: str = "2.0",
) -> dict[str, str]:
    """
    Генерирует конкретные значения параметров обфускации по стратегии и оператору.
    Возвращает dict с capitalized ключами: Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4, I1
    Значения возвращаются как строки.
    """
    # Обработка legacy пресетов
    if strategy in LEGACY_PRESET_MAP:
        mapped_strategy, mapped_carrier = LEGACY_PRESET_MAP[strategy]
        strategy = mapped_strategy
        if carrier is None:
            carrier = mapped_carrier

    # Получение базовой стратегии
    strat = STRATEGIES.get(strategy)
    if not strat:
        strat = STRATEGIES["wired"]
        strategy = "wired"

    # Применение оверрайдов оператора
    jc_range = strat.jc_range
    jmin_range = strat.jmin_range
    jmax_delta_range = strat.jmax_delta_range
    s1_range = strat.s1_range
    s2_range = strat.s2_range
    s3_range = strat.s3_range
    s4_range = strat.s4_range
    i1_mode = strat.i1_mode

    if carrier and carrier in CARRIER_OVERRIDES:
        override = CARRIER_OVERRIDES[carrier]
        if override.jc_range is not None:
            jc_range = override.jc_range
        if override.jmin_range is not None:
            jmin_range = override.jmin_range
        if override.jmax_delta_range is not None:
            jmax_delta_range = override.jmax_delta_range
        if override.s1_range is not None:
            s1_range = override.s1_range
        if override.s2_range is not None:
            s2_range = override.s2_range
        if override.i1_mode is not None:
            i1_mode = override.i1_mode

    # Инициализация рандомайзера
    local_random = random.Random(seed) if seed is not None else random

    # Генерация параметров
    jc = local_random.randint(jc_range[0], jc_range[1])
    jmin = local_random.randint(jmin_range[0], jmin_range[1])
    jmax_delta = local_random.randint(jmax_delta_range[0], jmax_delta_range[1])
    jmax = min(jmin + jmax_delta, JMAX_MAX)

    s1, s2, s3, s4 = _draw_paddings(
        local_random,
        protocol_mode=protocol_mode,
        s1_range=s1_range,
        s2_range=s2_range,
        s3_range=s3_range,
        s4_range=s4_range,
    )

    # Генерация уникальных заголовков H1-H4
    h_vals: list[int] = []
    while len(h_vals) < 4:
        candidate = local_random.randint(10000, 2000000000)
        if candidate in (1, 2, 3, 4):
            continue
        if any(abs(candidate - existing) < 1000 for existing in h_vals):
            continue
        h_vals.append(candidate)

    h1, h2, h3, h4 = h_vals

    # Генерация I1
    if i1_mode == "random":
        i1_len = local_random.randint(24, 32)
        i1 = "".join(local_random.choices("0123456789abcdef", k=i1_len * 2))
    else:
        i1 = ""

    return {
        "Jc": str(jc),
        "Jmin": str(jmin),
        "Jmax": str(jmax),
        "S1": str(s1),
        "S2": str(s2),
        "S3": str(s3),
        "S4": str(s4),
        "H1": str(h1),
        "H2": str(h2),
        "H3": str(h3),
        "H4": str(h4),
        "I1": i1,
    }


def list_presets() -> list[dict]:
    """Возвращает список доступных пресетов (для обратной совместимости)."""
    legacy_info = {
        "default": ("Default (проводной интернет)", "Универсальный пресет для проводного интернета."),
        "mobile": ("Mobile (универсальный для мобильных DPI)", "Jc=3 фиксированный, узкий Jmax. Для мобильных с ТСПУ."),
        "tele2": ("Tele2 (Россия)", "Jc=3 обязателен (Jc=4 ~30% успеха, Jc=5 <5%)."),
        "yota": ("Yota (Россия)", "Узкий Jmax обязателен — Jmax>300 блокируется."),
        "megafon": ("Мегафон (регионы)", "Без параметра I1 — иначе блокировка."),
        "beeline": ("Билайн (Россия)", "Работает default preset."),
        "tattelecom": ("Таттелеком / Летай", "Mobile preset подходит."),
    }
    return [{"name": name, "label": label, "description": desc} for name, (label, desc) in legacy_info.items()]


def list_strategies() -> list[dict]:
    """Возвращает список доступных стратегий."""
    return [{"name": k, "label": v.label, "description": v.description} for k, v in STRATEGIES.items()]


def list_carriers(strategy: str = "mobile") -> list[dict]:
    """Возвращает список операторов для стратегии."""
    out = []
    out.append(
        {"name": "generic", "label": "📶 Универсальный мобильный", "description": "Подходит большинству операторов"}
    )
    for k, v in CARRIER_OVERRIDES.items():
        if v.base_strategy == strategy or (strategy == "wired" and k == "beeline"):
            out.append({"name": k, "label": v.label, "description": v.description})
    return out


def validate_params(params: dict, protocol_mode: str = "2.0") -> tuple[bool, str]:
    """
    Валидирует параметры обфускации.
    Возвращает (True, "") или (False, "сообщение об ошибке").
    """
    try:

        def get_int(k):
            val = params.get(k, 0)
            if isinstance(val, str) and val.isdigit():
                return int(val)
            return int(val)

        jc = get_int("Jc")
        if jc < JC_MIN or jc > JC_MAX:
            return False, f"Jc={jc} вне диапазона ({JC_MIN}-{JC_MAX})"

        jmin = get_int("Jmin")
        if jmin < 0 or jmin > JMIN_MAX:
            return False, f"Jmin={jmin} вне диапазона (0-{JMIN_MAX})"

        jmax = get_int("Jmax")
        if jmax < 0 or jmax > JMAX_MAX:
            return False, f"Jmax={jmax} вне диапазона (0-{JMAX_MAX})"
        if jmax < jmin:
            return False, f"Jmax ({jmax}) меньше Jmin ({jmin})"

        s1 = get_int("S1")
        if s1 < 0 or s1 > JMIN_MAX:
            return False, f"S1={s1} вне диапазона (0-{JMIN_MAX})"

        s2 = get_int("S2")
        if s2 < 0 or s2 > JMIN_MAX:
            return False, f"S2={s2} вне диапазона (0-{JMIN_MAX})"

        # Проверка критического ограничения
        if s1 + 56 == s2:
            return False, "Нарушено ограничение обфускации: S1 + 56 == S2 (детектируемый fingerprint)"

        s3 = get_int("S3")
        if s3 < 0 or s3 > S3_MAX:
            return False, f"S3={s3} вне диапазона (0-{S3_MAX})"

        s4 = get_int("S4")
        if s4 < 0 or s4 > S4_MAX:
            return False, f"S4={s4} вне диапазона (0-{S4_MAX})"

        if str(protocol_mode).strip() not in ("", "2.0"):
            for field, value in (("S1", s1), ("S2", s2), ("S3", s3), ("S4", s4)):
                if value < AWG3_PADDING_MIN:
                    return False, (
                        f"Режим {protocol_mode}: {field}={value} меньше {AWG3_PADDING_MIN} — "
                        "защите заголовка не хватит нонса"
                    )

        # Валидация H1-H4 (до uint32), диапазонов и уникальности. Значение заголовка бывает и
        # диапазоном — так его выдаёт установщик и так его принимает ядро; для проверки уникальности
        # берём начало диапазона (совпавшие начала означают пересечение).
        h_vals = []
        for key in ("H1", "H2", "H3", "H4"):
            text = str(params.get(key, 0)).strip()
            if "-" in text:
                begin, _, end = text.partition("-")
                try:
                    low, high = int(begin.strip()), int(end.strip())
                except ValueError:
                    return False, f"{key}={text} не является числом или диапазоном"
                if low < 0 or high > 4294967295 or low > high:
                    return False, f"{key}={text} вне диапазона (0-4294967295)"
                h_vals.append(low)
                continue
            v = get_int(key)
            if v < 0 or v > 4294967295:
                return False, f"{key}={v} вне диапазона (0-4294967295)"
            h_vals.append(v)

        if len(set(h_vals)) != 4:
            return (
                False,
                f"Заголовки H1-H4 должны быть уникальными (получено: H1={h_vals[0]}, H2={h_vals[1]}, H3={h_vals[2]}, H4={h_vals[3]})",
            )

        i1 = params.get("I1", "")
        if i1:
            if not isinstance(i1, str):
                return False, "I1 должен быть строкой"
            if not (i1.startswith("<") and i1.endswith(">")):
                if not all(c in "0123456789abcdefABCDEF" for c in i1):
                    return False, "I1 содержит не-hex символы"

        return True, ""
    except Exception as e:
        return False, f"Ошибка валидации параметров: {e}"
