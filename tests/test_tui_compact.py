from hydra.ui import tui


def test_menu_shows_brief_descriptions(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")

    assert tui.menu([("1", "Действие", "Краткое пояснение")], "МЕНЮ") == "1"

    output = capsys.readouterr().out
    assert "Действие" in output
    # Краткое описание пункта теперь показывается — оператору не надо угадывать.
    assert "Краткое пояснение" in output
    # Пункты без описания не добавляют пустой строки.
    capsys.readouterr()
    tui.menu([("0", "Назад", "")], "МЕНЮ")
    plain = capsys.readouterr().out
    assert plain.count("│") // 2 <= 2, "пункт без описания — одна строка"
    assert "╭" in output
    assert "╔" not in output
    assert "ULTIMATE" in tui.BANNER


def test_progress_bar_tolerates_non_finite_values():
    assert tui._bar(float("nan"), 10, width=4).endswith("0%")
