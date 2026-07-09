"""tests/test_mieru_presets.py — Тесты для модуля Mieru presets."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.mieru.presets import list_presets, get_preset, get_preset_base64


def test_list_presets_returns_all_four():
    """list_presets() возвращает все 4 пресета."""
    presets = list_presets()
    assert len(presets) == 4
    names = [pr["name"] for pr in presets]
    assert "disabled" in names
    assert "basic" in names
    assert "medium" in names
    assert "aggressive" in names


def test_get_preset_by_name():
    """get_preset() возвращает верный пресет по его имени."""
    pr = get_preset("medium")
    assert pr["name"] == "medium"
    assert "nonce" in pr["config"]


def test_get_preset_invalid_fallback():
    """При неверном имени get_preset() делает fallback на basic."""
    pr = get_preset("non_existent_preset_xyz")
    assert pr["name"] == "basic"


def test_presets_base64_values():
    """Проверяет правильность генерации base64 protobuf строк для всех пресетов."""
    assert get_preset_base64("disabled") == "GgIIACoECAAQAA=="
    assert get_preset_base64("basic") == "GgQIARAK"
    assert get_preset_base64("medium") == "GgQIARAKIggIARABGAYgCCoFCEAQgAE="
    assert get_preset_base64("aggressive") == "EAEaBAgBEBQiBAgAEAEqBgiAARD/AQ=="
