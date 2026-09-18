from hydra.ui import tui


def test_menu_is_compact_by_default(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")

    assert tui.menu([("1", "Действие", "Длинное пояснение")], "МЕНЮ") == "1"

    output = capsys.readouterr().out
    assert "Действие" in output
    assert "Длинное пояснение" not in output
    assert "╭" in output
    assert "╔" not in output
    assert "ULTIMATE" in tui.BANNER


def test_progress_bar_tolerates_non_finite_values():
    assert tui._bar(float("nan"), 10, width=4).endswith("0%")
