from hydra.ui.protocol_ui import (
    protocol_label,
    protocol_menu_title,
    protocol_state,
    protocol_status_panel,
    status_badge,
)


def test_protocol_names_are_product_facing():
    assert protocol_label("amneziawg") == "AmneziaWG"
    assert protocol_label("naive") == "NaiveProxy"
    assert protocol_label("calls") == "Hydra VK Tunnel"
    assert protocol_menu_title("wdtt") == "QWDTT · УПРАВЛЕНИЕ"


def test_protocol_state_distinguishes_disabled_and_failed():
    assert "Отключён" in protocol_state(True, False, False)
    assert "Не работает" in protocol_state(True, True, False)
    assert "Не установлен" in protocol_state(False, False, False)


def test_status_badges_are_explicit_without_relying_on_colour():
    assert "✓ РАБОТАЕТ" in status_badge({"running": True})
    assert "○ ОТКЛЮЧЁН" in status_badge({"installed": True})
    assert "✕ СБОЙ" in status_badge({"installed": True, "enabled": True})
    assert "— НЕ УСТАНОВЛЕН" in status_badge({})
    assert "! ОШИБКА СТАТУСА" in status_badge({"error": "boom"})
    assert "! ЛИШНИЙ ПРОЦЕСС" in status_badge({"running": True, "drift": "unexpectedly_running"})
    assert "! НЕИЗВЕСТНО" in status_badge({"drift": "unknown"})


def test_protocol_panel_has_canonical_field_order(capsys):
    protocol_status_panel(
        "anytls",
        installed=True,
        enabled=True,
        running=True,
        port=443,
        details=[("Домен", "vpn.example")],
    )
    output = capsys.readouterr().out
    assert output.index("Состояние") < output.index("Установлен")
    assert output.index("Установлен") < output.index("Включён")
    assert output.index("Включён") < output.index("Порт")
    assert "AnyTLS" in output
    assert "vpn.example" in output


def test_long_detail_wraps_under_its_column_instead_of_being_cut(capsys):
    value = (
        "padding 500-2000 Б · post 1000000 Б · буфер 30 · "
        "сессия 30-120 с · заголовков 2"
    )

    protocol_status_panel(
        "vless",
        installed=True,
        enabled=True,
        running=True,
        port=443,
        details=[("Параметры", value)],
    )

    output = capsys.readouterr().out
    assert "..." not in output
    assert "заголовков 2" in output
    body = [line for line in output.splitlines() if line.startswith("  ║")]
    assert len({len(_visible(line)) for line in body}) == 1


def test_every_panel_row_keeps_the_same_visible_width(capsys):
    protocol_status_panel(
        "vless",
        installed=True,
        enabled=True,
        running=True,
        port=443,
        details=[
            ("Профиль", "Максимальная маскировка"),
            ("Домен", "heisenberg.example.com"),
        ],
    )

    body = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("  ║")
    ]
    assert body
    assert len({len(_visible(line)) for line in body}) == 1


def _visible(line: str) -> str:
    from hydra.ui.tui import _strip

    return _strip(line)
