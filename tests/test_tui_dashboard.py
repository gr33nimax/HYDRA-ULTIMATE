from hydra.ui.tui import dashboard_menu


def test_dashboard_menu_renders_one_composed_frame(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "0")

    choice = dashboard_menu(
        [
            ("СОСТОЯНИЕ УЗЛА", ["🟢 Sing-Box  запущен"]),
            ("СЛУЖБЫ", ["🐍 Протоколы  7 / 10 активны"]),
            ("ГИДРА СОВЕТУЕТ", ["💬 Одна голова хорошо, а десять — лучше."]),
        ],
        [("0", "🚪 Выход", "")],
        banner="HYDRA\nMulti-Protocol Proxy & Routing Orchestrator",
        options_header="УПРАВЛЕНИЕ",
    )

    output = capsys.readouterr().out
    assert choice == "0"
    assert output.count("╔") == 1
    assert output.count("╚") == 1
    assert "HYDRA" in output
    assert "СОСТОЯНИЕ УЗЛА" in output
    assert "СЛУЖБЫ" in output
    assert "ГИДРА СОВЕТУЕТ" in output
    assert "УПРАВЛЕНИЕ" in output
