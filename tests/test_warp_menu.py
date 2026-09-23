from types import SimpleNamespace

from hydra.ui.plugin_managers._warp_menu import _status_lines


def test_disabled_status_marks_routes_inactive_and_missing_target_invalid():
    lines = _status_lines(
        SimpleNamespace(installed=True, enabled=False, running=False),
        ["Finland"],
        ["direct", "warp_Finland"],
        {"ext:google_ai": "warp"},
        {"google_ai": {"name": "GoogleAI"}},
    )
    rendered = "\n".join(lines)

    assert "маршруты WARP сейчас не применяются" in rendered
    assert "warp (недоступен)" in rendered
